"""User-facing local Seed-MPC sessions. No raw-update oracle or experiment imports.

Local bootstrap still trusts the host administrator. Role configuration is
separate; the client roster is inferred from data shards. Remote deployment is future work.
"""
import argparse
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import tomllib
import uuid

import numpy as np
import tomli_w

from .crypto import Identity, ProtocolError, canonical, digest
from .seed_mpc_assets import configure_tls, free_port_base, write_private, stage_circuit_sources, circuit_bytes, CIRCUIT_SHA256
from .seed_mpc_backend import pin_backend
from .seed_mpc_committee import CoordinatorState
from .seed_mpc_compile import compile_circuit
from .seed_mpc_model import load_model_config, model_contract
from .seed_mpc_policy import SeedMPCPolicy
from .seed_mpc_prss import MASK_MODE, local_source_hashes
from .seed_mpc_session import load_deployment, rpc
from .seed_mpc_launcher import run as flower_run

USER_PROTOCOL = 'seed-mpc-user-session-v1'
ROLE_PROTOCOL = 'seed-mpc-role-config-v1'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, body):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(canonical(body))


def read_role(path, role):
    path = Path(path).resolve()
    body = json.loads(path.read_text())
    if body.get('protocol') != ROLE_PROTOCOL or body.get('role') != role:
        raise ProtocolError('wrong role configuration')
    return body


def checked_user_deployment(path):
    deployment, committee = load_deployment(path)
    if (deployment.get('user_session') != USER_PROTOCOL
            or deployment.get('trusted_test_audit') is not False
            or deployment.get('training', {}).get('mode') != 'custom-model'
            or deployment.get('mask_mode') != MASK_MODE
            or committee.snapshot_version != 2
            or deployment.get('test_fault') is not None
            or deployment.get('test_dropout_schedule')
            or deployment.get('training', {}).get('test_poisoning')):
        raise ProtocolError('user session requires audit-free certified custom-model execution')
    return deployment, committee


def prepare(output, installation, model_config, *, rounds=2, seed=42, timeout=300,
            collection_window_ms=30000, policy_config=None, compile_cache=None,
            chunk_blocks=None, component_input='stock-private-v1', communication_meter=False, clients=None,
            compile_timeout=180,simulation_workers=1,client_loop='static-unrolled-v1',rpc_material='inline-v1'):
    """Prepare a fresh local session and individual role configs, never overwrite."""
    if (type(rounds) is not int or not 1 <= rounds <= 20
            or type(seed) is not int or seed < 0
            or type(timeout) is not int or not 180 <= timeout <= 3600
            or type(collection_window_ms) is not int or not 1 <= collection_window_ms <= 3600000
            or type(communication_meter) is not bool
            or type(compile_timeout) is not int or not 1<=compile_timeout<=7200
            or type(simulation_workers) is not int or not 1<=simulation_workers<=32):
        raise ProtocolError('invalid local session settings')
    if component_input not in ('stock-private-v1', 'holder-checked-direct-v1'):
        raise ProtocolError('unsupported component input')
    if client_loop not in ('static-unrolled-v1','compact-runtime-v1'):
        raise ProtocolError('unsupported client loop')
    if rpc_material not in ('inline-v1','prepared-reference-v1'):raise ProtocolError('unsupported RPC material mode')
    spec, initial, options, train_paths, test_path, embedded_policy = load_model_config(model_config, seed, expected_clients=clients)
    dimension = spec['schema']['dimension']
    client_count = len(train_paths)
    if policy_config and embedded_policy is not None:
        raise ProtocolError('choose one static policy source')
    supplied = json.loads(Path(policy_config).read_text()) if policy_config else embedded_policy
    if (not isinstance(supplied, dict) or set(supplied)-set(SeedMPCPolicy.__dataclass_fields__)
            or not {'coordinate_cap', 'squared_threshold', 'scale'} <= set(supplied)
            or supplied.get('dimension', dimension) != dimension or supplied.get('max_clients', client_count) != client_count):
        raise ProtocolError('explicit static policy must match model and client shard count')
    policy = SeedMPCPolicy(**{'dimension': dimension, 'max_clients': client_count, **supplied})
    if policy.word_bits != 16:
        raise ProtocolError('seeded-mask implementation requires 16-bit wire words')
    policy.validate_ring(64)
    if chunk_blocks is None:
        chunk_blocks = 64 if dimension >= 512 else 4
    if type(chunk_blocks) is not int or not 1 <= chunk_blocks <= 64:
        raise ProtocolError('invalid chunk blocks')
    installation = Path(installation).resolve()
    binary = installation/'rep4-ring-party.x'
    backend_pin = pin_backend(installation)
    if component_input == 'holder-checked-direct-v1' and 'rep4-holder-checked-native-import-v1' not in backend_pin['applied_patches']:
        raise ProtocolError('native component import requires pinned importer build')
    if communication_meter and not backend_pin['applied_patches']:
        raise ProtocolError('communication meter requires pinned observer build')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    workspace = output/'mpc'
    workspace.mkdir()
    party_port = free_port_base(4)
    client_port = free_port_base(4)
    while abs(party_port-client_port) < 8:
        client_port = free_port_base(4)
    config = {**asdict(policy), 'clients': client_count, 'parties': 4, 'backend': 'rep4', 'ring_bits': 64,
        'backend_prime': 1 << 64, 'domain_modulus': 1 << 64, 'seed_encoding': 'packed64',
        'rep4_input_mode': 'replicated-triples-v1', 'output_mode': 'native-public', 'output_length': 0,
        'coordinate_circuit': 'chunked', 'chunk_blocks': chunk_blocks, 'round_slots': rounds,
        'widths': policy.widths(), 'client_port': client_port, 'runtime_client_port': True,
        'certified_stream': True, 'backend_pin_hash': digest(backend_pin), 'snapshot_version': 2,
        'mask_mode': MASK_MODE, 'component_input': component_input, 'public_agreement': 'checked-open-v1',
        'collection_window_ms': collection_window_ms, 'mask_source_sha256': local_source_hashes(),
        **({'communication_meter': True} if communication_meter else {})}
    if client_loop!='static-unrolled-v1':config['client_loop']=client_loop
    write(workspace/'policy.json', config)
    sources = stage_circuit_sources(workspace)
    circuits = workspace/'Programs/Circuits'
    circuits.mkdir()
    (circuits/'aes_128.txt').write_bytes(circuit_bytes(installation))
    if compile_cache is None:
        compile_cache = Path.home()/'.cache/trustlessfl/circuits'
    compilation = compile_circuit(workspace, installation, config, sources, CIRCUIT_SHA256, compile_cache,
                                  build_timeout=compile_timeout)
    artifacts = {p.relative_to(workspace/'Programs').as_posix(): sha(p)
        for folder in ('Bytecode', 'Schedules') for p in (workspace/'Programs'/folder).rglob('*') if p.is_file()}
    training = {'mode': 'custom-model', 'seed': seed, **options}
    execution_hash = digest({'artifacts': artifacts, 'binary': sha(binary), 'aes': CIRCUIT_SHA256,
        'sources': sources, 'config': config, 'backend_pin': digest(backend_pin),
        'model': model_contract(spec), 'training': training})
    actors = configure_tls(workspace, 4, client_count)
    client_root = output/'clients'
    client_root.mkdir(mode=0o700)
    identities = [Identity.generate(f'A{i}') for i in range(4)]
    preparation = {'mask_mode': MASK_MODE, 'aggregator_public': {i.name: i.public() for i in identities},
        'session_id': uuid.uuid4().hex, 'policy_hash': policy.policy_hash,
        'execution_hash': execution_hash, 'installation': str(installation), 'snapshot_version': 2,
        'client_count': client_count}
    write(output/'client-preparation.json', preparation)
    env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1]),
           'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1'}
    registry = {i.name: i.public() for i in identities}
    registrations = []
    for slot in range(client_count):
        directory = client_root/f'C{slot}'
        subprocess.run([sys.executable, '-m', 'trustlessfl.seed_mpc_client_app', '--directory', str(directory),
            '--preparation', str(output/'client-preparation.json'), '--slot', str(slot)],
            env=env, check=True, timeout=30)
        public = json.loads((directory/'public-registration.json').read_text())
        registry[f'C{slot}'] = public['public']
        registrations.append(public['envelope'])
        (directory/'Player-Data').symlink_to(actors[f'C{slot}']/'Player-Data', target_is_directory=True)
        shutil.copyfile(train_paths[slot], directory/'train.npz')
        (directory/'train.npz').chmod(0o600)
    for slot in range(4):
        packets = actors[f'P{slot}']/'seed-packets'
        packets.mkdir(mode=0o700)
        for client in range(client_count):
            shutil.copyfile(client_root/f'C{client}/component-packets/A{slot}.json', packets/f'C{client}.json')
            (packets/f'C{client}.json').chmod(0o600)
    services = []
    while len(services) < 4:
        port = free_port_base(1)
        url = f'http://127.0.0.1:{port}'
        if url not in services and min(abs(port-party_port), abs(port-client_port)) >= 8:
            services.append(url)
    app = output/'app'
    shutil.copytree(Path(__file__).parent, app/'trustlessfl', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    plugin_target = app/'trustlessfl/user_model.py'
    shutil.copyfile(spec['plugin'], plugin_target)
    model_spec = {**spec, 'plugin': str(plugin_target)}
    test = output/'coordinator/public-test.npz'
    test.parent.mkdir()
    shutil.copyfile(test_path, test)
    deployment = {'user_session': USER_PROTOCOL, 'protocol': 'seed-mpc-local-deployment-v1',
        'rpc_material':rpc_material,
        'mask_mode': MASK_MODE, 'mask_source_sha256': config['mask_source_sha256'],
        'workspace': str(workspace), 'native_binary': str(binary), 'backend_pin': backend_pin,
        'trusted_test_audit': False, 'role_isolation': False, 'binary_sha256': sha(binary),
        'aes_sha256': CIRCUIT_SHA256, 'config_sha256': sha(workspace/'policy.json'),
        'artifacts': artifacts, 'program': 'seed_mpc_chunked_session-policy.json', 'party_port': party_port,
        'services': services, 'timeout': timeout, 'rounds': rounds, 'training': training,
        'initial_model': initial.tolist(), 'test_data': str(test), 'test_fault': None,
        'compilation': compilation, 'model_adapter': model_spec,
        **({'communication_meter': True} if communication_meter else {}),
        'committee': {'policy': asdict(policy), 'session_id': preparation['session_id'], 'epoch': 1,
            'snapshot_version': 2, 'collection_window_ms': collection_window_ms,
            'clients': [f'C{i}' for i in range(client_count)], 'aggregators': [f'A{i}' for i in range(4)],
            'registry': registry, 'registrations': registrations, 'execution_hash': execution_hash}}
    write(output/'deployment.json', deployment)
    deployment_sha = sha(output/'deployment.json')
    for slot, identity in enumerate(identities):
        actor = actors[f'P{slot}']
        write_private(actor/'service-private.json', canonical({'identity': identity.private(),
            'actor': str(actor), 'deployment_sha256': deployment_sha}))
        write_private(actor/'role.json', canonical({'protocol': ROLE_PROTOCOL, 'role': 'aggregator',
            'slot': slot, 'deployment': str(output/'deployment.json'), 'private': str(actor/'service-private.json')}))
    for slot in range(client_count):
        directory = client_root/f'C{slot}'
        subprocess.run([sys.executable, '-m', 'trustlessfl.seed_mpc_client_app', '--directory', str(directory),
            '--pin', str(output/'deployment.json')], env=env, check=True, timeout=30)
        write_private(directory/'role.json', canonical({'protocol': ROLE_PROTOCOL, 'role': 'client',
            'slot': slot, 'client-directory': str(directory), 'deployment': str(output/'deployment.json')}))
    app_config = {'deployment-file': str(output/'deployment.json'), 'output-dir': str(output/'runtime-results'),
        'num-clients': client_count, 'backend': 'numpy', 'simulation-workers': simulation_workers, 'seed-mpc-runtime-guard': True,
        'seed-mpc-runtime-guard-sha256': sha(Path(__file__).with_name('seed_mpc_flower_runtime.py')),
        'runtime-cli-timeout': max(900, timeout*rounds+600)}
    flower = {'project': {'name': 'trustlessfl', 'version': '0.1.0',
        'description': 'Local certified Seed-MPC federated classification', 'license': 'MIT',
        'requires-python': '>=3.12', 'dependencies': ['flwr[simulation]==1.36.0', 'numpy>=2.5.0',
            'cryptography>=46.0.7,<47', f"torch=={importlib.metadata.version('torch').split('+')[0]}"]},
        'tool': {'flwr': {'app': {'components': {'serverapp': 'trustlessfl.seed_mpc_server_app:app',
            'clientapp': 'trustlessfl.seed_mpc_client_app:app'}, 'config': app_config}}}}
    # Existing placeholder metadata is retained only for local FAB construction; no account setup.
    flower['tool']['flwr']['app']['publisher'] = 'trustlessfl'
    (app/'pyproject.toml').write_text(tomli_w.dumps(flower))
    write(output/'coordinator/role.json', {'protocol': ROLE_PROTOCOL, 'role': 'coordinator',
        'deployment': str(output/'deployment.json'), 'app': str(app), 'run_config': app_config})
    write(output/'session.json', {'protocol': USER_PROTOCOL, 'session_id': preparation['session_id'],
        'dimension': dimension, 'rounds': rounds, 'trusted_test_audit': False, 'client_count': client_count,
        'aggregator_count': 4, 'compilation': compilation,
        'scope': 'local single-UID bootstrap; role configs do not provide OS or operator isolation'})
    return deployment


def check_client_config(path):
    role = read_role(path, 'client')
    slot = role.get('slot')
    if type(slot) is not int or slot < 0:
        raise ProtocolError('invalid client slot')
    directory = Path(role['client-directory']).resolve()
    private = json.loads((directory/'client.json').read_text())
    if private.get('test_audit') is not False:
        raise ProtocolError('user client raw audit must be disabled')
    deployment, committee = checked_user_deployment(role['deployment'])
    if slot >= len(committee.clients):
        raise ProtocolError('client slot outside registered roster')
    if (private['deployment_sha256'] != sha(role['deployment'])
            or Path(private['deployment']).resolve() != Path(role['deployment']).resolve()):
        raise ProtocolError('client deployment binding differs')
    identity = Identity.from_private(private['identity'])
    if identity.name != committee.clients[slot] or identity.public() != committee.registry[identity.name]:
        raise ProtocolError('client identity/config differs')
    return role


def check_coordinator_config(path):
    role = read_role(path, 'coordinator')
    _, committee = checked_user_deployment(role['deployment'])
    app = Path(role['app']).resolve()
    actual = tomllib.loads((app/'pyproject.toml').read_text())['tool']['flwr']['app']
    if (actual['config'] != role['run_config']
            or type(actual['config'].get('num-clients', len(committee.clients))) is not int
            or actual['config'].get('num-clients', len(committee.clients)) != len(committee.clients)
            or Path(role['run_config']['deployment-file']).resolve() != Path(role['deployment']).resolve()
            or actual['components'] != {'serverapp': 'trustlessfl.seed_mpc_server_app:app',
                                        'clientapp': 'trustlessfl.seed_mpc_client_app:app'}):
        raise ProtocolError('coordinator app/config binding differs')
    return role


def aggregator_command(config):
    role = read_role(config, 'aggregator')
    checked_user_deployment(role['deployment'])
    if type(role.get('slot')) is not int or role['slot'] not in range(4):
        raise ProtocolError('invalid aggregator slot')
    return [sys.executable, '-m', 'trustlessfl.seed_mpc_service', '--deployment', role['deployment'],
            '--private', role['private'], '--slot', str(role['slot'])]


def verify_public_results(output):
    """Authenticate public transcript and replay aggregate transitions, never open client data."""
    output = Path(output).resolve()
    deployment, committee = checked_user_deployment(output/'deployment.json')
    files = list((output/'runtime-results').glob('run-*/results.json'))
    if len(files) != 1:
        raise ProtocolError('exactly one completed Flower result required')
    result = json.loads(files[0].read_text())
    records = result['records']
    if len(records) != deployment['rounds']:
        raise ProtocolError('incomplete certified rounds')
    verification = output/'public-verification.sqlite'
    if verification.exists():
        raise ProtocolError('public verifier state already exists; do not rerun session')
    state = CoordinatorState(committee, verification, deployment['initial_model'], create=True)
    try:
        if result['models'][0] != state.head()['model'] or len(result['models']) != len(records)+1:
            raise ProtocolError('public initial model sequence differs')
        collections = result.get('collection_receipts', [])
        if len(collections) != len(records):
            raise ProtocolError('missing collection proofs')
        checks = []
        for index, (record, collection) in enumerate(zip(records, collections, strict=True)):
            manifest = record['manifest']
            context = committee.check_manifest(manifest)
            if collection['round'] != context.round_id:
                raise ProtocolError('collection round differs')
            clients = [name for name, flag in zip(committee.clients, manifest['presence'], strict=True) if flag]
            if len(collection['certificates']) != len(clients):
                raise ProtocolError('incomplete receipt set')
            for name, proof in zip(clients, collection['certificates'], strict=True):
                packets = [p for p in manifest['inputs'] if p['sender'] == name]
                submission = committee.submission(context, manifest['parent_decision'], name, packets)
                committee.check_receipt_certificate(submission, proof)
            if not state.apply(manifest, record['input_certificate'], record['result_certificate']):
                raise ProtocolError('duplicate public decision')
            if result['models'][index+1] != state.head()['model']:
                raise ProtocolError('public model/aggregate differs')
            value = record['result_certificate']['body']['result']
            checks.append({'round': context.round_id, 'status': value['status'],
                           'accepted_count': value.get('count'), 'certificates_valid': True})
        if result['final_head'] != state.head():
            raise ProtocolError('public final head differs')
    finally:
        state.ledger.close()
    summary = {'protocol': USER_PROTOCOL, 'completed': True, 'dimension': committee.policy.dimension, 'client_count': len(committee.clients),
        'rounds': checks, 'trusted_test_audit': False, 'verification': 'public certificates and model transitions only',
        'independent_retraining_verified': False, 'scope': 'local single-UID; static malicious aggregator bound f<=1',
        'metrics': result['metrics'], 'compile_invocations': deployment['compilation']['compile_invocations']}
    write(output/'summary.json', summary)
    return summary


def stop_registration_helpers(output, client_count):
    for slot in range(client_count):
        marker = output/f'clients/C{slot}/registration-process.json'
        if not marker.exists():
            continue
        pid = json.loads(marker.read_text()).get('pid')
        if type(pid) is not int or pid <= 1:
            continue
        try:
            args = (Path('/proc')/str(pid)/'cmdline').read_bytes().split(b'\0')
            expected = str(output/f'clients/C{slot}/seed-input.json').encode()
            if b'trustlessfl.seed_mpc_external_client' in args and expected in args and os.getpgid(pid) == pid:
                os.killpg(pid, signal.SIGTERM)
        except (FileNotFoundError, ProcessLookupError):
            pass


def run(output):
    output = Path(output).resolve()
    deployment, committee = checked_user_deployment(output/'deployment.json')
    for slot in range(len(committee.clients)):
        check_client_config(output/f'clients/C{slot}/role.json')
    coordinator = check_coordinator_config(output/'coordinator/role.json')
    if Path(coordinator['app']).resolve() != output/'app':
        raise ProtocolError('coordinator app is outside prepared session')
    # A durable one-shot marker is written before launching any native process.
    # Unknown or interrupted execution is never implicitly retried with the same seeds.
    marker = output/'run-started.json'
    write_private(marker, canonical({'protocol': USER_PROTOCOL, 'started_ns': time.time_ns()}))
    processes, logs = [], []
    env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1]),
        'TRUSTLESSFL_SEED_CLIENT_ROOT': str(output/'clients'), 'TRUSTLESSFL_SEED_USER_MODE': '1',
        'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1'}
    old = {k: os.environ.get(k) for k in ('TRUSTLESSFL_SEED_CLIENT_ROOT', 'TRUSTLESSFL_SEED_USER_MODE')}
    try:
        for slot in range(4):
            actor = Path(deployment['workspace'])/f'P{slot}'
            log = (actor/'service.log').open('x')
            logs.append(log)
            processes.append(subprocess.Popen(aggregator_command(actor/'role.json'), cwd=output, env=env,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True))
        deadline = time.monotonic()+30
        for slot, url in enumerate(deployment['services']):
            while True:
                if processes[slot].poll() is not None:
                    raise ProtocolError('aggregator startup failed')
                try:
                    rpc(url, 'head', timeout=1)
                    break
                except ProtocolError:
                    if time.monotonic() > deadline:
                        raise ProtocolError('aggregator startup timeout')
                    time.sleep(.1)
        os.environ.update({k: env[k] for k in old})
        flower_run(output)
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for log in logs:
            log.close()
        stop_registration_helpers(output, len(committee.clients))
    return verify_public_results(output)


def status(output):
    output = Path(output).resolve()
    if (output/'summary.json').is_file():
        return json.loads((output/'summary.json').read_text())
    session = json.loads((output/'session.json').read_text())
    return {**session, 'completed': False,
            'state': 'started-or-interrupted; create a fresh session' if (output/'run-started.json').exists() else 'prepared'}


def main():
    parser = argparse.ArgumentParser(description='Audit-free local Flower/Seed-MPC classification')
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare', help='prepare a fresh local session; raw audit disabled')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--model-config', type=Path, required=True)
    p.add_argument('--mp-spdz-dir', type=Path, required=True)
    p.add_argument('--policy-config', type=Path)
    p.add_argument('--compile-cache', type=Path)
    p.add_argument('--clients', type=int, help='optional consistency check; inferred from train_data otherwise')
    p.add_argument('--rounds', type=int, default=2)
    p.add_argument('--seed', type=int, default=42)
    p.add_argument('--timeout', type=int, default=300)
    p.add_argument('--collection-window-ms', type=int, default=30000)
    p.add_argument('--chunk-blocks', type=int)
    p.add_argument('--component-input', choices=('stock-private-v1', 'holder-checked-direct-v1'), default='stock-private-v1')
    p.add_argument('--communication-meter', action='store_true')
    p.add_argument('--compile-timeout',type=int,default=180,help='cold compilation seconds, up to 7200; does not alter circuit/cache recipe')
    p.add_argument('--simulation-workers',type=int,default=1,help='local Ray workers, 1..32; independent of registered client count')
    p.add_argument('--client-loop',choices=('static-unrolled-v1','compact-runtime-v1'),default='static-unrolled-v1')
    p.add_argument('--rpc-material',choices=('inline-v1','prepared-reference-v1'),default='inline-v1')
    for name in ('run', 'status'):
        commands.add_parser(name).add_argument('--output', type=Path, required=True)
    commands.add_parser('aggregator').add_argument('--config', type=Path, required=True)
    commands.add_parser('check-client').add_argument('--config', type=Path, required=True)
    commands.add_parser('check-coordinator').add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        kwargs = vars(args).copy()
        kwargs.pop('command')
        output, installation, model = (kwargs.pop(k) for k in ('output', 'mp_spdz_dir', 'model_config'))
        prepare(output, installation, model, **kwargs)
        print(json.dumps(status(output), ensure_ascii=False))
    elif args.command == 'run':
        print(json.dumps(run(args.output), ensure_ascii=False))
    elif args.command == 'status':
        print(json.dumps(status(args.output), ensure_ascii=False))
    elif args.command == 'aggregator':
        subprocess.run(aggregator_command(args.config), check=True)
    elif args.command == 'check-coordinator':
        check_coordinator_config(args.config)
        print(json.dumps({'role': 'coordinator', 'valid': True}))
    elif args.command == 'check-client':
        role = check_client_config(args.config)
        print(json.dumps({'role': 'client', 'slot': role['slot'], 'valid': True, 'trusted_test_audit': False}))


if __name__ == '__main__':
    main()

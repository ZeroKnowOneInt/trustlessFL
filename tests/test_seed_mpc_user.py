"""User runtime guards, package resources and public-only result verification."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tomllib
import pytest
from trustlessfl.crypto import Identity, ProtocolError, canonical, digest
from trustlessfl.seed_mpc_assets import stage_circuit_sources
from trustlessfl.seed_mpc_committee import SeedCommittee, CoordinatorState
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_user import checked_user_deployment, check_client_config, read_role, status, verify_public_results, USER_PROTOCOL, ROLE_PROTOCOL
from trustlessfl.seed_mpc_wire import RoundContext
ROOT = Path(__file__).resolve().parents[1]


def test_packaged_circuit_sources_preserve_reviewed_bytes(tmp_path):
    for name, expected in stage_circuit_sources(tmp_path).items():
        raw = (tmp_path/'Programs/Source'/name).read_bytes()
        assert raw == (ROOT/'mpc/Programs/Source'/name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected


def test_user_cli_imports_without_experiment_package(tmp_path):
    code = """
import importlib.abc, sys
class BlockExperiments(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'experiments' or fullname.startswith('experiments.'):
            raise RuntimeError('user runtime imported experiment tooling')
sys.meta_path.insert(0, BlockExperiments())
sys.path.insert(0, sys.argv[1])
from trustlessfl.seed_mpc_user import main
sys.argv = ['trustlessfl-seed-mpc', '--help']
main()
"""
    result = subprocess.run([sys.executable, '-c', code, str(ROOT)], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert 'check-client' in result.stdout


def test_default_flower_app_selects_seed_mpc():
    config = tomllib.loads((ROOT/'pyproject.toml').read_text())
    app = config['tool']['flwr']['app']
    assert app['components'] == {'serverapp': 'trustlessfl.seed_mpc_server_app:app', 'clientapp': 'trustlessfl.seed_mpc_client_app:app'}
    assert app['config']['deployment-file'] == 'UNCONFIGURED'
    assert config['project']['scripts']['trustlessfl-seed-mpc'] == 'trustlessfl.seed_mpc_user:main'


@pytest.fixture
def public_session(tmp_path, monkeypatch):
    from trustlessfl import seed_mpc_user as user
    ids = {name: Identity.generate(name) for name in [*(f'C{i}' for i in range(4)), *(f'A{i}' for i in range(4))]}
    policy = SeedMPCPolicy(2, 4, 20000, 400000000)
    execution = digest('pinned execution')
    registrations = [ids[f'C{i}'].sign({'protocol': 'seed-mpc-registration-v2', 'session_id': 'fixture', 'committee_epoch': 1, 'client_id': f'C{i}', 'slot': i, 'key_handle': f'h{i}', 'policy_hash': policy.policy_hash, 'execution_hash': execution}) for i in range(4)]
    committee = SeedCommittee(policy, 'fixture', 1, [f'C{i}' for i in range(4)], [f'A{i}' for i in range(4)], {name: identity.public() for name, identity in ids.items()}, registrations, execution, [0.0, 0.0], snapshot_version=2)
    deployment = {'user_session': USER_PROTOCOL, 'trusted_test_audit': False, 'mask_mode': 'rep4-seeded-components-v1', 'training': {'mode': 'custom-model'}, 'rounds': 1, 'initial_model': [0.0, 0.0], 'compilation': {'compile_invocations': 0}}
    monkeypatch.setattr(user, 'load_deployment', lambda _: (deployment, committee))
    state = CoordinatorState(committee, tmp_path/'fixture.sqlite', [0.0, 0.0], create=True)
    context = RoundContext('fixture', 1, 1, digest([0.0, 0.0]), policy.policy_hash)
    packets = [ids[name].sign(context.payload(policy, client_id=name, key_handle=committee.handles[i], values=[40000, 50000])) for i, name in enumerate(committee.clients)]
    manifest = committee.manifest(context, state.head()['decision'], packets, presence=[1]*4)
    proofs = []
    for name, packet in zip(committee.clients, packets, strict=True):
        submission = committee.submission(context, manifest['parent_decision'], name, [packet])
        proofs.append(committee.receipt_certificate(submission, [ids[a].sign(committee.receipt_body(submission)) for a in committee.aggregators[:3]]))
    input_body = committee.input_body(manifest)
    input_qc = committee.certificate(input_body, [ids[a].sign(input_body) for a in committee.aggregators[:3]])
    def save(value):
        body = committee.result_body(manifest, value, [0.0, 0.0])
        qc = committee.certificate(body, [ids[a].sign(body) for a in committee.aggregators[:3]])
        state.apply(manifest, input_qc, qc)
        result = {'records': [{'manifest': manifest, 'input_certificate': input_qc, 'result_certificate': qc}], 'models': [[0.0, 0.0], state.head()['model']], 'metrics': [{}, {}], 'collection_receipts': [{'round': 1, 'certificates': proofs}], 'final_head': state.head()}
        directory = tmp_path/'runtime-results/run-1'
        directory.mkdir(parents=True)
        path = directory/'results.json'
        path.write_bytes(canonical(result))
        return path, result
    yield tmp_path, deployment, committee, save, ids
    state.ledger.close()


@pytest.mark.parametrize('fault', ['audit', 'mode', 'mask', 'fault', 'dropout', 'poisoning'])
def test_user_session_rejects_test_and_legacy_paths(public_session, fault):
    root, d, _, _, _ = public_session
    if fault == 'audit': d['trusted_test_audit'] = True
    if fault == 'mode': d['training']['mode'] = 'fixture'
    if fault == 'mask': d['mask_mode'] = 'secret-aes-v1'
    if fault == 'fault': d['test_fault'] = 'uncertified-model'
    if fault == 'dropout': d['test_dropout_schedule'] = {'1': {'C0': {}}}
    if fault == 'poisoning': d['training']['test_poisoning'] = {'case': 'clean'}
    with pytest.raises(ProtocolError): checked_user_deployment(root/'deployment.json')


@pytest.mark.parametrize('value', [{'status': 'ok', 'count': 4, 'sum': [20, -12]}, {'status': 'abort'}])
def test_public_verifier_needs_no_client_data_or_seeds(public_session, value):
    root, _, _, save, _ = public_session
    save(value)
    summary = verify_public_results(root)
    assert summary['completed']
    assert summary['independent_retraining_verified'] is False
    assert summary['rounds'][0]['accepted_count'] == value.get('count')
    assert not (root/'clients').exists()
    assert status(root) == summary


@pytest.mark.parametrize('fault', ['receipt-signature', 'missing-receipt', 'model', 'result-signature'])
def test_public_verifier_rejects_tampered_transcript(public_session, fault):
    root, _, _, save, _ = public_session
    path, result = save({'status': 'ok', 'count': 4, 'sum': [20, -12]})
    if fault == 'receipt-signature': result['collection_receipts'][0]['certificates'][0]['votes'][0]['signature'] = '00'*64
    if fault == 'missing-receipt': result['collection_receipts'][0]['certificates'].pop()
    if fault == 'model': result['models'][1][0] += 1
    if fault == 'result-signature': result['records'][0]['result_certificate']['votes'][0]['signature'] = '00'*64
    path.write_bytes(canonical(result))
    with pytest.raises((ProtocolError, ValueError, KeyError)): verify_public_results(root)
    assert not (root/'summary.json').exists()


def test_client_role_refuses_raw_audit_and_wrong_slot(public_session):
    root, _, _, _, ids = public_session
    deployment = root/'deployment.json'; deployment.write_text('{}')
    directory = root/'client'; directory.mkdir()
    private = {'test_audit': False, 'deployment': str(deployment), 'deployment_sha256': hashlib.sha256(deployment.read_bytes()).hexdigest(), 'identity': ids['C0'].private()}
    path = directory/'client.json'; path.write_bytes(canonical(private))
    config = {'protocol': ROLE_PROTOCOL, 'role': 'client', 'slot': 0, 'client-directory': str(directory), 'deployment': str(deployment)}
    role = directory/'role.json'; role.write_bytes(canonical(config))
    assert check_client_config(role)['slot'] == 0
    private['test_audit'] = True; path.write_bytes(canonical(private))
    with pytest.raises(ProtocolError): check_client_config(role)
    private['test_audit'] = False; path.write_bytes(canonical(private))
    config['slot'] = 1; role.write_bytes(canonical(config))
    with pytest.raises(ProtocolError): check_client_config(role)
    with pytest.raises(ProtocolError): read_role(role, 'aggregator')


@pytest.mark.parametrize('prior_state', ['started', 'completed'])
def test_user_run_never_restarts_used_session(public_session, monkeypatch, prior_state):
    from trustlessfl import seed_mpc_user as user
    root, _, _, _, _ = public_session
    (root/'run-started.json').write_bytes(canonical({'state': prior_state}))
    monkeypatch.setattr(user, 'check_client_config', lambda _: {})
    monkeypatch.setattr(user, 'check_coordinator_config', lambda _: {'app': str(root/'app')})
    def forbidden(*args, **kwargs):
        pytest.fail('reused session launched a process')
    monkeypatch.setattr(user.subprocess, 'Popen', forbidden)
    with pytest.raises(FileExistsError): user.run(root)


@pytest.mark.parametrize('fault', [None, 'deployment', 'component', 'run-config'])
def test_coordinator_role_is_bound_to_public_app_config(public_session, fault):
    import tomli_w
    from trustlessfl.seed_mpc_user import check_coordinator_config
    root, _, _, _, _ = public_session
    app = root/'app'; app.mkdir()
    deployment = str(root/'deployment.json')
    components = {'serverapp': 'trustlessfl.seed_mpc_server_app:app', 'clientapp': 'trustlessfl.seed_mpc_client_app:app'}
    config = {'deployment-file': deployment, 'output-dir': str(root/'runtime-results')}
    role = {'protocol': ROLE_PROTOCOL, 'role': 'coordinator', 'deployment': deployment, 'app': str(app), 'run_config': dict(config)}
    if fault == 'deployment': role['deployment'] = str(root/'other.json')
    if fault == 'component': components['serverapp'] = 'trustlessfl.server_app:app'
    if fault == 'run-config': config['output-dir'] = str(root/'other-results')
    (app/'pyproject.toml').write_text(tomli_w.dumps({'tool': {'flwr': {'app': {'components': components, 'config': config}}}}))
    path = root/'coordinator.json'; path.write_bytes(canonical(role))
    if fault:
        with pytest.raises(ProtocolError): check_coordinator_config(path)
    else:
        assert check_coordinator_config(path) == role

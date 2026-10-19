"""Trusted development validation of generic user sessions and N-client native fixtures.

All test inputs/seeds belong to this local oracle. Public reports contain no
individual updates, identity secrets or seed strings. No Hub operations.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
import numpy as np

from examples.seed_mpc_custom.create_local_data import prepare as prepare_data
from trustlessfl.crypto import Identity, ProtocolError, canonical, digest
from trustlessfl.seed_mpc_user import prepare, run, aggregator_command
from trustlessfl.seed_mpc_assets import write_private
from trustlessfl.seed_mpc_session import load_deployment, committee_rpc, rpc
from trustlessfl.seed_mpc_committee import CoordinatorState
from trustlessfl.seed_mpc_model import train_custom, evaluate_custom
from trustlessfl.seed_mpc_prss import combined_mask, seed_packet
from trustlessfl.seed_mpc_training import quantize
from trustlessfl.seed_mpc_wire import RoundContext
from trustlessfl.seed_mpc_meter import global_partition

ROOT = Path(__file__).resolve().parents[1]


def write(path, value):
    with Path(path).open('xb') as stream:
        stream.write(canonical(value))


def reference_training(output):
    d, c = load_deployment(output/'deployment.json')
    result = json.loads(next((output/'runtime-results').glob('run-*/results.json')).read_text())
    model = np.asarray(d['initial_model'], dtype=np.float64)
    checks = []
    for r, record in enumerate(result['records'], 1):
        rows = []
        for slot in range(len(c.clients)):
            with np.load(output/f'clients/C{slot}/train.npz', allow_pickle=False) as saved:
                delta, _ = train_custom(d['model_adapter'], model, saved['x'], saved['y'], slot=slot, round_id=r, training=d['training'])
            row = quantize(delta, c.policy)
            if all(abs(v) <= c.policy.coordinate_cap for v in row) and sum(v*v for v in row) <= c.policy.squared_threshold:
                rows.append(row)
        total = [sum(row[j] for row in rows) for j in range(c.policy.dimension)]
        expected = {'status': 'ok', 'count': len(rows), 'sum': total} if len(rows) >= c.policy.minimum_accepted else {'status': 'abort'}
        if record['result_certificate']['body']['result'] != expected:
            raise AssertionError('native result differs from independent training')
        model = np.asarray(c.next_model(model.tolist(), expected), dtype=np.float64)
        if not np.array_equal(model, np.asarray(result['models'][r], dtype=np.float64)):
            raise AssertionError('model transition differs')
        with np.load(d['test_data'], allow_pickle=False) as saved:
            metric = evaluate_custom(d['model_adapter'], model, saved['x'], saved['y'])
        if metric != result['metrics'][r]:
            raise AssertionError('public evaluation differs')
        if record['manifest']['presence'] != [1]*len(c.clients) or len(rows) != len(c.clients):
            raise AssertionError('all-present training was not completed')
        checks.append({'round': r, 'count': len(rows), 'integer_sum_exact': True, 'model_exact': True, 'evaluation_exact': True})
    if list(output.glob('clients/*/audit/round-*.json')):
        raise AssertionError('raw user audit created')
    return {'clients': len(c.clients), 'aggregators': len(c.aggregators), 'dimension': c.policy.dimension,
        'rounds': checks, 'raw_audit_files': 0, 'widths': c.policy.widths(),
        'compilation': d['compilation'], 'communication': result['communication']['native']}


def stop_processes(processes):
    for p in processes:
        if p.poll() is None:
            try: os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError: pass
    for p in processes:
        try: p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()


def native_fixture(output, *, registration_fault=False):
    d, c = load_deployment(output/'deployment.json')
    clients = len(c.clients)
    if registration_fault:
        # Highest slot, component 1 held by A0: a correctly signed/encrypted but
        # inconsistent holder copy must be checked beyond the original N=4 batch.
        private = json.loads((output/f'clients/C{clients-1}/client.json').read_text())
        identity = Identity.from_private(private['identity'])
        seeds = [bytes.fromhex(x) for x in private['component_seeds']]
        altered = bytearray(seeds[1]); altered[0] ^= 0x80; seeds[1] = bytes(altered)
        packet = seed_packet(identity, seeds, c.registrations[-1]['body'], 0, c.registry['A0'])
        (Path(d['workspace'])/f'P0/seed-packets/C{clients-1}.json').write_bytes(canonical(packet))
    write_private(output/'run-started.json', canonical({'trusted_native_fixture': True}))
    env = {**os.environ, 'PYTHONPATH': str(ROOT), 'OPENBLAS_NUM_THREADS': '1', 'OMP_NUM_THREADS': '1'}
    processes, logs = [], []
    state = None
    try:
        for party in range(4):
            actor = Path(d['workspace'])/f'P{party}'
            log = (actor/'service.log').open('x'); logs.append(log)
            processes.append(subprocess.Popen(aggregator_command(actor/'role.json'), env=env, cwd=ROOT,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True))
        deadline = time.monotonic()+30
        for party, url in enumerate(d['services']):
            while True:
                if processes[party].poll() is not None: raise ProtocolError('fixture service startup failed')
                try: rpc(url, 'head', timeout=1); break
                except ProtocolError:
                    if time.monotonic() > deadline: raise ProtocolError('fixture startup timeout')
                    time.sleep(.1)
        helpers = []
        for slot in range(clients):
            directory = output/f'clients/C{slot}'
            log = (directory/'client.log').open('x'); logs.append(log)
            helper = subprocess.Popen([sys.executable, '-m', 'trustlessfl.seed_mpc_external_client',
                '--mp-spdz-dir', str(Path(d['native_binary']).parent), '--private-input', str(directory/'seed-input.json'),
                '--config', str(Path(d['workspace'])/'policy.json'), '--output', str(directory/'registration-submitted.json')],
                env=env, cwd=directory, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            helpers.append(helper); processes.append(helper)
        if registration_fault:
            try: committee_rpc(d, 'ready')
            except ProtocolError: pass
            else: raise AssertionError('last client holder mismatch accepted')
            for party in range(4):
                text = (Path(d['workspace'])/f'P{party}/native.log').read_text()
                if 'inconsistent component seed registration' not in text:
                    raise AssertionError('expected active seed consistency failure not observed')
                if 'SEED_MPC_PUBLIC ' in text or 'SEED_MPC_REG_CHECKED' in text:
                    raise AssertionError('unchecked registration released an output')
                with sqlite3.connect(f'file:{Path(d["workspace"])/f"P{party}"/"rounds.sqlite"}?mode=ro', uri=True) as db:
                    if db.execute('SELECT count(*) FROM rounds').fetchone()[0] != 0:
                        raise AssertionError('unchecked registration entered a round')
                    if db.execute('SELECT round FROM head WHERE id=1').fetchone()[0] != 0:
                        raise AssertionError('registration failure changed model head')
            return {'clients': clients, 'aggregators': 4, 'registration_fault_rejected': True,
                    'fault_slot': clients-1, 'result_certificates': 0}
        ready = committee_rpc(d, 'ready')
        if any(x['registration_checked'] is not True for x in ready): raise AssertionError('registration unchecked')
        for helper in helpers:
            if helper.wait(timeout=30) != 0: raise AssertionError('registration helper failed')
        state = CoordinatorState(c, output/'fixture-coordinator.sqlite', d['initial_model'], create=True)
        cases = []
        for round_id in range(1, 5):
            head = state.head()
            context = RoundContext(c.session_id, c.epoch, round_id, digest(head['model']), c.policy.policy_hash)
            opened = committee_rpc(d, 'collect-open', {'context': context.__dict__, 'parent_decision': head['decision']})
            presence = [1]*clients
            if round_id == 2: presence[-1] = 0
            if round_id == 4: presence = [1]+[0]*(clients-1)
            inputs, proofs, valid_rows = [], [], []
            for slot in range(clients):
                if not presence[slot]: continue
                row = [0]*c.policy.dimension
                if round_id == 1: row[-1] = 20000
                elif round_id == 2: row[-1] = -20000
                elif round_id == 3:
                    row[0], row[-1] = 3, 4
                    if slot == 0: row[-1] = 20001
                    if slot == 1: row = [20000]*7+[0]*(c.policy.dimension-7)
                else: row[-1] = 20000
                if all(abs(v)<=c.policy.coordinate_cap for v in row) and sum(v*v for v in row)<=c.policy.squared_threshold:
                    valid_rows.append(row)
                private = json.loads((output/f'clients/C{slot}/client.json').read_text())
                identity = Identity.from_private(private['identity'])
                masks = combined_mask([bytes.fromhex(x) for x in private['component_seeds']],
                    c.registrations[slot]['body'], round_id, c.policy.dimension, c.policy.word_bits)
                wire = [(v+m)%c.policy.modulus for v,m in zip(row,masks,strict=True)]
                packets = [identity.sign(context.payload(c.policy, client_id=identity.name, key_handle=c.handles[slot],
                    values=wire[offset:offset+32], offset=offset)) for offset in range(0, c.policy.dimension, 32)]
                submission = c.submission(context, head['decision'], identity.name, packets)
                proof = c.receipt_certificate(submission, committee_rpc(d, 'collect', {'submission': submission}))
                inputs.extend(packets); proofs.append(proof)
            if not all(presence):
                cutoff = max(x['deadline_ms'] for x in opened)
                while time.time_ns()//1000000 < cutoff: time.sleep(.02)
            manifest = c.manifest(context, head['decision'], inputs, presence=presence)
            referenced=d.get('rpc_material')=='prepared-reference-v1'
            votes = committee_rpc(d, 'prepare', {'manifest': manifest, 'receipt_certificates': proofs},
                                  **({'sequential':True} if referenced else {}))
            input_qc = c.certificate(c.input_body(manifest), votes)
            ref={'round_id':round_id,'input_hash':digest(manifest)}
            votes = (committee_rpc(d,'execute-reference',{**ref,'input_certificate':input_qc}) if referenced else
                     committee_rpc(d, 'execute', {'manifest': manifest, 'input_certificate': input_qc}))
            qc = c.certificate(votes[0]['body'], votes)
            expected = ({'status': 'ok', 'count': len(valid_rows), 'sum': [sum(row[j] for row in valid_rows) for j in range(c.policy.dimension)]}
                        if len(valid_rows)>=c.policy.minimum_accepted else {'status': 'abort'})
            if qc['body']['result'] != expected: raise AssertionError('generic presence/boundary/native SUM differs')
            if not state.apply(manifest, input_qc, qc): raise AssertionError('fixture model apply failed')
            applied=(committee_rpc(d,'decide-reference',{**ref,'result_certificate':qc},sequential=True) if referenced else
                     committee_rpc(d, 'decide', {'manifest': manifest, 'result_certificate': qc}))
            if applied != [True]*4:
                raise AssertionError('fixture committee apply differs')
            cases.append({'round': round_id, 'presence': presence, 'result': expected, 'exact': True})
        done = committee_rpc(d, 'finish')
        if any(x['native_exit'] != 0 or x['head'] != state.head() for x in done): raise AssertionError('native fixture did not finish')
        return {'clients': clients, 'aggregators': 4, 'registration_checked': True, 'cases': cases,
                'communication': global_partition([x['communication'] for x in done])}
    finally:
        if state is not None: state.ledger.close()
        stop_processes(processes)
        for log in logs: log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mp-spdz-dir', type=Path, required=True)
    parser.add_argument('--clients', type=int, nargs='+', default=[4,8,16])
    parser.add_argument('--native-fixtures', action='store_true')
    parser.add_argument('--registration-fault', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {'training': [], 'native_fixtures': [], 'registration_faults': [],
              'scope': 'trusted local development reference; four aggregators; not multi-host isolation'}
    os.environ['PATH'] = str(ROOT/'.venv/bin')+':/usr/local/bin:/usr/bin:/bin'
    for clients in args.clients:
        print(f'VALIDATING Flower clients={clients}', flush=True)
        data = prepare_data(output/f'data-{clients}', clients=clients)
        run_dir = output/f'flower-{clients}'
        prepare(run_dir, args.mp_spdz_dir, data, clients=clients, rounds=2, collection_window_ms=20000,
                compile_cache=ROOT/'.cache/seed-mpc-circuits', component_input='holder-checked-direct-v1', communication_meter=True)
        run(run_dir)
        report['training'].append(reference_training(run_dir))
        write(output/f'training-{clients}.json', report['training'][-1])
        if args.native_fixtures:
            print(f'VALIDATING native dropout/wrap clients={clients}', flush=True)
            fixture = output/f'native-{clients}'
            prepare(fixture, args.mp_spdz_dir, data, clients=clients, rounds=4, collection_window_ms=2000,
                    compile_cache=ROOT/'.cache/seed-mpc-circuits', component_input='holder-checked-direct-v1', communication_meter=True)
            report['native_fixtures'].append(native_fixture(fixture))
            write(output/f'native-{clients}.json', report['native_fixtures'][-1])
    if args.registration_fault:
        clients = max(args.clients)
        print(f'VALIDATING last client seed mismatch clients={clients}', flush=True)
        fixture = output/f'registration-fault-{clients}'
        prepare(fixture, args.mp_spdz_dir, output/f'data-{clients}/model.json', clients=clients, rounds=4,
                collection_window_ms=2000, compile_cache=ROOT/'.cache/seed-mpc-circuits',
                component_input='holder-checked-direct-v1', communication_meter=True)
        report['registration_faults'].append(native_fixture(fixture, registration_fault=True))
    report['passed'] = True
    write(output/'verification.json', report)
    print(json.dumps({'passed': True, 'client_counts': args.clients, 'report': str(output/'verification.json')}), flush=True)


if __name__ == '__main__': main()

"""Sequential native Flower checks for user models and cross-session compilation reuse."""
import argparse
import json
from pathlib import Path

from experiments.prepare_seed_mpc_custom_example import prepare
from experiments.run_seed_mpc_flower import stage, run, verify_run, ROOT
from trustlessfl.crypto import ProtocolError, canonical


def validate(output, installation):
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=False)
    cfg = prepare(output/'data-mlp53')
    other = prepare(output/'data-mlp73', hidden=7)
    cache = output/'circuit-cache'
    records = []
    for name, config, expect_hit in [('mlp53-first', cfg, False), ('mlp53-reuse', cfg, True), ('mlp73-first', other, False)]:
        directory = output/name
        deployment = stage(directory, installation, mode='custom-model', model_config=config,
            compile_cache=cache, rounds=2, timeout=300, snapshot_version=2,
            collection_window_ms=10000, communication_meter=True,
            component_input='holder-checked-direct-v1')
        if deployment['compilation']['hit'] != expect_hit:
            raise ProtocolError('unexpected compile cache reuse decision')
        run(directory)
        result = verify_run(directory)
        records.append({'case': name, 'dimension': result['dimension'], 'rounds': result['rounds'],
            'passed': result['passed'], 'compilation': result['compilation'],
            'integer_sum_model_metrics_exact': result['protocol_correctness_passed'],
            'learning_workload_completed': result['learning_workload_completed'],
            'metrics': result['metrics'], 'session_id': deployment['committee']['session_id'],
            'execution_hash': deployment['committee']['execution_hash'],
            'model_schema_hash': deployment['model_adapter']['schema_hash'],
            'client_port': json.loads((directory/'mpc/policy.json').read_text())['client_port']})
    first, repeat, second = records
    if (first['compilation']['key'] != repeat['compilation']['key']
            or first['compilation']['key'] == second['compilation']['key']
            or first['model_schema_hash'] == second['model_schema_hash']
            or first['session_id'] == repeat['session_id']
            or first['execution_hash'] == repeat['execution_hash']
            or first['metrics'] != repeat['metrics']):
        raise ProtocolError('cache/session/model independence check failed')
    result = {'passed': True, 'cases': records, 'compile_invocations': sum(r['compilation']['compile_invocations'] for r in records),
        'scope': 'two toy PyTorch classifier shapes, fresh private sessions, active Rep4 import and official local Flower; no Hub publication'}
    (output/'verification.json').write_bytes(canonical(result))
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--mp-spdz-dir', type=Path, default=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1')
    args = p.parse_args()
    print(json.dumps(validate(args.output, args.mp_spdz_dir), indent=2))

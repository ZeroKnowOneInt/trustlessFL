"""Trusted local FMNIST poisoning oracle; no protocol or server permissions."""
import argparse
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import time

import numpy as np

from experiments.run_fmnist_flower import read_dataset
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_training import initial_lenet, train_lenet, lenet_model
from trustlessfl.fmnist import tensor_images

ROOT = Path(__file__).resolve().parents[1]
CASES = ('clean', 'out-of-bound', 'norm-overflow', 'sign-flip', 'bounded-50', 'bounded-100', 'label-flip')
POLICY = SeedMPCPolicy(61706, 4, 20000, 2500000000)


def vector_hash(v):
    return hashlib.sha256(np.asarray(v, dtype='<f8').tobytes()).hexdigest()


def save_json(path, body):
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(body, ensure_ascii=False, indent=2) + '\n')
    os.replace(temp, path)


def norm2(q):
    return sum(int(v) ** 2 for v in q)


def accepted(q, policy=POLICY):
    return bool(np.all(np.abs(q) <= policy.coordinate_cap)) and norm2(q) <= policy.squared_threshold


def canonical(q, policy=POLICY):
    # A signed wire's effective representative, independent of intended input.
    half = policy.modulus // 2
    return (np.asarray(q, dtype=np.int64) + half) % policy.modulus - half


def bounded(q, fraction, policy=POLICY):
    target = int(policy.squared_threshold * fraction ** 2)
    if not np.any(q) or target == 0:
        return np.zeros_like(q)
    direction = -q.astype(np.float64)
    cap = policy.coordinate_cap
    def at(scale):
        return np.rint(np.clip(direction * scale, -cap, cap)).astype(np.int64)
    lo, hi = 0., 1.
    # Saturation can make a sparse direction unable to reach the requested norm.
    for _ in range(60):
        if norm2(at(hi)) >= target:
            break
        hi *= 2
    else:
        result = at(hi)
        assert accepted(result, policy)
        return result
    for _ in range(80):
        mid = (lo + hi) / 2
        if norm2(at(mid)) <= target:
            lo = mid
        else:
            hi = mid
    result = at(lo)
    assert accepted(result, policy) and norm2(result) <= target
    return result


def attack(q, case, policy=POLICY):
    q = np.asarray(q, dtype=np.int64)
    if case in ('clean', 'label-flip'):
        return q.copy()
    if case == 'norm-overflow':
        from trustlessfl.seed_mpc_poisoning_fixture import norm_overflow
        return norm_overflow(q,policy)
    if case == 'sign-flip':
        return -q
    if case.startswith('bounded-'):
        return bounded(q, .5 if case == 'bounded-50' else 1., policy)
    if case == 'out-of-bound':
        # Keep all values canonical so rejection isn't hidden by modulo aliasing.
        result = np.clip(q, -policy.coordinate_cap, policy.coordinate_cap)
        index = int(np.argmax(np.abs(q)))
        result[index] = (1 if q[index] >= 0 else -1) * (policy.coordinate_cap + 1)
        assert not accepted(result, policy)
        return result
    raise ValueError(case)


def flip_labels(y):
    result = y.copy()
    result[y == 0] = 6
    result[y == 6] = 0
    return result


def metrics(vector, x, y):
    import torch
    model = lenet_model(vector)
    model.eval()
    confusion = np.zeros((10, 10), dtype=np.int64)
    loss = 0.
    with torch.no_grad():
        for start in range(0, len(y), 256):
            labels = torch.from_numpy(y[start:start+256].astype(np.int64))
            logits = model(tensor_images(x[start:start+256], 'cpu'))
            pred = logits.argmax(1).numpy()
            np.add.at(confusion, (labels.numpy(), pred), 1)
            loss += float(torch.nn.functional.cross_entropy(logits, labels, reduction='sum'))
    return {'accuracy': float(np.trace(confusion) / len(y)), 'loss': loss / len(y),
            'class_accuracy': (confusion.diagonal() / confusion.sum(1)).tolist(),
            'class_0_to_6': float(confusion[0, 6] / confusion[0].sum()),
            'class_6_to_0': float(confusion[6, 0] / confusion[6].sum()),
            'confusion': confusion.tolist()}


def run(output, seeds, cases, rounds=5, malicious=1):
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    cache = output / 'trusted-private-cache'
    cache.mkdir(exist_ok=True, mode=0o700)
    data = read_dataset(ROOT / '.cache/fashion-mnist/FashionMNIST/raw')
    sources = {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
               ['experiments/run_seed_mpc_poisoning.py', 'trustlessfl/seed_mpc_training.py',
                'trustlessfl/seed_mpc_policy.py', 'trustlessfl/seed_mpc_poisoning_fixture.py', 'trustlessfl/fmnist.py']}
    config = {'kind': 'trusted-plaintext-oracle-not-MPC', 'policy': asdict(POLICY),
              'seeds': seeds, 'cases': cases, 'rounds': rounds, 'malicious_clients': malicious,
              'malicious_slots': list(range(malicious)),
              'training': {'epochs': 1, 'batch_size': 64, 'learning_rate': .01,
                           'momentum': .9, 'weight_decay': .0005, 'device': 'cpu'},
              'source_sha256': sources,
              'versions': {p: importlib.metadata.version(p) for p in ('numpy', 'torch')},
              'data_sha256': {k: hashlib.sha256(v.tobytes()).hexdigest() for k,v in data.items()}}
    config_path = output / 'configuration.json'
    if config_path.exists() and json.loads(config_path.read_text()) != config:
        raise ValueError('Refuse resume with changed configuration/source/data')
    save_json(config_path, config)
    started = time.monotonic()
    for seed in seeds:
        order = np.random.default_rng(seed).permutation(len(data['train_y']))
        shards = [(data['train_x'][i], data['train_y'][i]) for i in np.array_split(order, 4)]
        for case in cases:
            path = output / f'seed-{seed}-{case}-m{malicious}.json'
            if path.exists() and json.loads(path.read_text()).get('status') == 'completed':
                print('ALREADY_COMPLETED', seed, case, flush=True)
                continue
            initial = initial_lenet(seed)
            models = {name: initial.copy() for name in ('mean', 'static-filter')}
            initial_metrics = metrics(initial, data['test_x'], data['test_y'])
            report = {'seed': seed, 'case': case, 'malicious_clients': malicious,
                      'status': 'running', 'initial_metrics': initial_metrics, 'rounds': []}
            save_json(path, report)
            for r in range(1, rounds+1):
                round_record = {'round': r, 'variants': {}}
                # Cache keyed by exact current model, round/slot/seed and labels.
                # Paths that diverge after filtering train on their own models.
                for variant, model in models.items():
                    t = time.monotonic()
                    updates = []
                    for slot, (x, y) in enumerate(shards):
                        flipped = slot < malicious and case == 'label-flip'
                        key = f'{seed}-{r}-{slot}-{int(flipped)}-{vector_hash(model)}'
                        file = cache / f'{key}.npz'
                        if file.exists():
                            with np.load(file, allow_pickle=False) as saved:
                                q = saved['q']
                        else:
                            delta, _ = train_lenet(
                                model, x, flip_labels(y) if flipped else y, seed=seed, slot=slot,
                                round_id=r, **{k:v for k,v in config['training'].items() if k != 'device'})
                            q = np.rint(delta * POLICY.scale).astype(np.int64)
                            np.savez_compressed(file, q=q)
                            file.chmod(0o600)
                        q = attack(q, case) if slot < malicious else q.copy()
                        effective = canonical(q)
                        if not np.array_equal(q, effective):
                            raise ValueError('Unexpected signed-wire alias; needs separate case')
                        updates.append(effective)
                    flags = [accepted(q) for q in updates]
                    keep = flags if variant == 'static-filter' else [True] * 4
                    count = sum(keep)
                    status = 'ok' if count >= POLICY.minimum_accepted else 'abort'
                    if status == 'ok':
                        total = np.sum([q for q,k in zip(updates,keep) if k], axis=0, dtype=np.int64)
                        model = model + total.astype(np.float64) / (POLICY.scale * count)
                        sum_hash = hashlib.sha256(total.astype('<i8').tobytes()).hexdigest()
                    else:
                        sum_hash = None
                    models[variant] = model
                    round_record['variants'][variant] = {
                        'status': status, 'accepted_count': count,
                        'static_filter_would_accept': sum(flags),
                        'malicious_passed_static': sum(flags[:malicious]) if case != 'clean' else 0,
                        'honest_rejected_static': sum(not v for v in flags[malicious:]) if case != 'clean' else sum(not v for v in flags),
                        'sum_sha256': sum_hash, 'model_sha256': vector_hash(model),
                        'metrics': metrics(model, data['test_x'], data['test_y']),
                        'wall_seconds': time.monotonic()-t}
                    print('ROUND', seed, case, variant, r, 'accepted', count,
                          'accuracy', round_record['variants'][variant]['metrics']['accuracy'], flush=True)
                report['rounds'].append(round_record)
                save_json(path, report)
            report['status'] = 'completed'
            save_json(path, report)
            summarize(output)
    summarize(output)
    print('MATRIX_COMPLETED', round(time.monotonic()-started, 2), flush=True)


def summarize(output):
    rows = [json.loads(p.read_text()) for p in sorted(output.glob('seed-*.json'))
            if json.loads(p.read_text()).get('status') == 'completed']
    clean = {(r['seed'], v): r['rounds'][-1]['variants'][v]['metrics']['accuracy']
             for r in rows if r['case'] == 'clean' for v in ('mean','static-filter')}
    summary = []
    for r in rows:
        for variant in ('mean','static-filter'):
            final = r['rounds'][-1]['variants'][variant]
            baseline = clean.get((r['seed'],variant))
            summary.append({'seed':r['seed'],'case':r['case'],'variant':variant,
                            'accuracy':final['metrics']['accuracy'],
                            'clean_degradation_percentage_points': None if baseline is None else 100*(baseline-final['metrics']['accuracy']),
                            'last_round_accepted':final['accepted_count']})
    save_json(output/'summary.json', {'scope':'trusted plaintext oracle; native MPC not executed by this runner',
                                    'completed_conditions':len(rows),'results':summary})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seeds', type=int, nargs='+', default=[42,43,44])
    parser.add_argument('--cases', choices=CASES, nargs='+', default=list(CASES))
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--malicious', type=int, choices=[1,2], default=1)
    args=parser.parse_args()
    if not 1 <= args.rounds <= 20: parser.error('rounds must be 1..20')
    run(args.output.resolve(), args.seeds, args.cases, args.rounds, args.malicious)

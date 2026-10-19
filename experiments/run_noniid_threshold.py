"""Trusted local static-threshold study, followed by actual Flower/Rep4 replay.

Private q caches and native input/identity files stay under .cache. Public output
contains research statistics and equality checks, never update vectors or seeds.
"""
import argparse
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import numpy as np

from experiments.run_fmnist_flower import read_dataset
from experiments.run_seed_mpc_poisoning import metrics, vector_hash
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_training import initial_lenet, train_lenet, evaluate_lenet

ROOT = Path(__file__).resolve().parents[1]
DISTRIBUTIONS = {'iid': None, 'moderate': .5, 'strong': .1}
RADII = (1., 2.5, 5., 10.)
TRAINING = dict(epochs=1, batch_size=64, learning_rate=.01, momentum=.9, weight_decay=.0005)
SOURCES = ('experiments/run_noniid_threshold.py', 'experiments/run_seed_mpc_flower.py',
           'experiments/run_seed_mpc_poisoning.py', 'trustlessfl/seed_mpc_training.py',
           'trustlessfl/seed_mpc_policy.py', 'trustlessfl/fmnist.py',
           'trustlessfl/seed_mpc_client_app.py', 'trustlessfl/seed_mpc_server_app.py')


def read(path): return json.loads(Path(path).read_text())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path, value):
    path = Path(path)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temp.replace(path)


def policy(radius):
    result = SeedMPCPolicy(61706, 4, 20000, int(round((10000*radius)**2)))
    result.validate_ring(64)
    return result


def balanced_partition(labels, seed, alpha):
    """Dirichlet weights -> balanced transportation, then integer marginals.

    Equal client sizes are enforced, so this is constrained label skew rather
    than unconstrained Dirichlet sampling. All indices are used exactly once.
    """
    if len(labels) % 4:
        raise ValueError('dataset size must be divisible by four')
    if alpha is None:
        return np.stack(np.array_split(np.random.default_rng(seed).permutation(len(labels)), 4))
    if not alpha > 0:
        raise ValueError('alpha must be positive')
    rng = np.random.default_rng(np.random.SeedSequence([seed, 2087]))
    classes = np.unique(labels)
    row_counts = np.array([np.sum(labels == k) for k in classes], dtype=np.int64)
    col_counts = np.full(4, len(labels)//4, dtype=np.int64)
    matrix = np.maximum(rng.dirichlet(np.full(4, alpha), size=len(classes)), 1e-100)
    # Iterative proportional fitting preserves relative preferences subject
    # to exact row/client marginals; cap iterations rather than silent drift.
    for _ in range(20000):
        matrix *= (row_counts / matrix.sum(axis=1))[:, None]
        matrix *= (col_counts / matrix.sum(axis=0))[None, :]
        if np.max(np.abs(matrix.sum(axis=1)-row_counts)) < 1e-7:
            break
    else:
        raise ValueError('balanced label allocation did not converge')
    counts = np.floor(matrix).astype(np.int64)
    row_need = row_counts-counts.sum(axis=1)
    col_need = col_counts-counts.sum(axis=0)
    scores = matrix-counts
    while row_need.sum():
        eligible = (row_need[:, None] > 0) & (col_need[None, :] > 0)
        k, slot = np.unravel_index(np.argmax(np.where(eligible, scores, -np.inf)), scores.shape)
        counts[k, slot] += 1
        row_need[k] -= 1
        col_need[slot] -= 1
        scores[k, slot] -= 1
    assert not np.any(col_need)
    shards = [[] for _ in range(4)]
    for k, label in enumerate(classes):
        indices = rng.permutation(np.flatnonzero(labels == label))
        offset = 0
        for slot in range(4):
            size = int(counts[k, slot])
            shards[slot].extend(indices[offset:offset+size].tolist())
            offset += size
    result = np.stack([rng.permutation(shard) for shard in shards])
    assert result.shape == (4, len(labels)//4)
    assert np.array_equal(np.sort(result.reshape(-1)), np.arange(len(labels)))
    return result


def partition_info(labels, indices):
    counts = [np.bincount(labels[index], minlength=10).tolist() for index in indices]
    probabilities = np.asarray(counts, dtype=np.float64)/indices.shape[1]
    entropies = [-float(np.sum(p[p > 0]*np.log2(p[p > 0]))) for p in probabilities]
    return {'rows_per_client': [len(i) for i in indices], 'class_counts': counts,
            'class_entropy_bits': entropies,
            'mean_class_entropy_bits': float(np.mean(entropies)),
            'indices_sha256': [hashlib.sha256(i.astype('<i8').tobytes()).hexdigest() for i in indices]}


def condition_name(seed, distribution, radius, rounds):
    return f'seed-{seed}-{distribution}-{("mean" if radius is None else "R"+str(radius))}-{rounds}r'


def condition(output, data, seed, distribution, radius, rounds):
    name = condition_name(seed, distribution, radius, rounds)
    destination = output/'oracle'/f'{name}.json'
    if destination.exists() and read(destination).get('completed'):
        print('ALREADY_COMPLETED', name, flush=True)
        return read(destination)
    indices = np.load(output/'partitions'/f'{seed}-{distribution}.npy', allow_pickle=False)
    shards = [(data['train_x'][i], data['train_y'][i]) for i in indices]
    active_policy = policy(5. if radius is None else radius)
    model = initial_lenet(seed)
    report = {'completed': False, 'seed': seed, 'distribution': distribution,
              'radius': radius, 'round_slots': rounds, 'policy': asdict(active_policy),
              'initial_metrics': metrics(model, data['test_x'], data['test_y']), 'rounds': []}
    write(destination, report)
    for r in range(1, rounds+1):
        started = time.monotonic()
        updates = []
        before_hash = vector_hash(model)
        for slot, (x, y) in enumerate(shards):
            key = f'{seed}-{distribution}-{r}-{slot}-{before_hash}'
            cache = output/'trusted-private-cache'/f'{key}.npz'
            if cache.exists():
                with np.load(cache, allow_pickle=False) as saved:
                    q = saved['q']
            else:
                delta, _ = train_lenet(model, x, y, seed=seed, slot=slot, round_id=r, **TRAINING)
                q = np.rint(delta*active_policy.scale).astype(np.int64)
                np.savez_compressed(cache, q=q)
                cache.chmod(0o600)
            if not np.array_equal(q, (q+32768)%65536-32768):
                raise ValueError('normal SGD input has wire alias; refuse unlabelled alias experiment')
            updates.append(q)
        norm2 = [sum(int(v)**2 for v in q) for q in updates]
        maxima = [int(np.max(np.abs(q))) for q in updates]
        coordinate_ok = [v <= active_policy.coordinate_cap for v in maxima]
        norm_ok = [v <= active_policy.squared_threshold for v in norm2]
        keep = [True]*4 if radius is None else [a and b for a, b in zip(coordinate_ok, norm_ok)]
        count = sum(keep)
        status = 'ok' if count >= active_policy.minimum_accepted else 'abort'
        total = None
        if status == 'ok':
            total = np.sum([q for q, k in zip(updates, keep) if k], axis=0, dtype=np.int64)
            model = model+total.astype(np.float64)/(active_policy.scale*count)
        row = {'round': r, 'status': status, 'count': count, 'accepted': keep,
               'coordinate_ok': coordinate_ok, 'norm_ok': norm_ok, 'norm2': norm2,
               'l2': [v**.5/active_policy.scale for v in norm2], 'max_coordinate_abs': maxima,
               'input_model_sha256': before_hash, 'model_sha256': vector_hash(model),
               'sum_sha256': None if total is None else hashlib.sha256(total.astype('<i8').tobytes()).hexdigest(),
               'metrics': metrics(model, data['test_x'], data['test_y']),
               'wall_seconds': time.monotonic()-started}
        report['rounds'].append(row)
        write(destination, report)
        print('ROUND', name, r, status, count, row['metrics']['accuracy'],
              'L2', [round(v, 3) for v in row['l2']], flush=True)
    report['completed'] = True
    report['rejected_per_client'] = [sum(not row['accepted'][i] for row in report['rounds']) for i in range(4)]
    report['abort_rounds'] = sum(row['status'] == 'abort' for row in report['rounds'])
    report['coordinate_failures'] = sum(sum(not v for v in row['coordinate_ok']) for row in report['rounds'])
    report['norm_failures'] = sum(sum(not v for v in row['norm_ok']) for row in report['rounds'])
    write(destination, report)
    print('COMPLETED_PLAIN', name, flush=True)
    return report


def summarized(rows):
    keys = sorted(set((r['distribution'], r['radius']) for r in rows), key=lambda k: (k[0], -1 if k[1] is None else k[1]))
    result = []
    for distribution, radius in keys:
        selected = [r for r in rows if r['distribution'] == distribution and r['radius'] == radius]
        values = [100*r['rounds'][-1]['metrics']['accuracy'] for r in selected]
        result.append({'distribution': distribution, 'radius': radius,
                       'seeds': [r['seed'] for r in selected], 'final_accuracy_percent': values,
                       'mean_accuracy_percent': float(np.mean(values)), 'std_percentage_points': float(np.std(values, ddof=1)),
                       'rejected': sum(sum(r['rejected_per_client']) for r in selected),
                       'submissions': sum(4*len(r['rounds']) for r in selected),
                       'rejected_per_client': np.sum([r['rejected_per_client'] for r in selected], axis=0).tolist(),
                       'abort_rounds': sum(r['abort_rounds'] for r in selected),
                       'coordinate_failures': sum(r['coordinate_failures'] for r in selected),
                       'norm_failures': sum(r['norm_failures'] for r in selected),
                       'mean_curve_percent': np.mean([[100*r['initial_metrics']['accuracy']]+[100*v['metrics']['accuracy'] for v in r['rounds']] for r in selected], axis=0).tolist()})
    return result


def choose(summary):
    # Preregistered descriptive ranking, not an unbiased held-out test estimate.
    candidates = [r for r in summary if r['distribution'] == 'strong' and r['radius'] is not None]
    best = sorted(candidates, key=lambda r: (-r['mean_accuracy_percent'], r['rejected'], r['radius'] != 5., r['radius']))[0]
    return {'distribution': 'strong', 'selected_radius': best['radius'],
            'native_radii': list(dict.fromkeys([5., best['radius']])),
            'rule': 'highest mean final test accuracy under strong skew, then fewer rejected, then R5, then smaller R; exploratory test-informed selection'}


def native(output, installation, seed, radius, rounds):
    from experiments.run_seed_mpc_flower import stage, run, verify_run
    root = output.parent
    index_path = root/'partitions'/f'{seed}-strong.npy'
    policy_path = root/f'policy-R{radius}.json'
    if not policy_path.exists():
        write(policy_path, asdict(policy(radius)))
    stage(output, installation, mode='fmnist-lenet5', seed=seed, rounds=rounds, timeout=1200,
          snapshot_version=2, collection_window_ms=600000, communication_meter=True,
          test_audit=True, chunk_blocks=64, component_input='holder-checked-direct-v1',
          compile_cache=ROOT/'.cache/noniid-threshold-circuits', policy_config=policy_path,
          test_train_indices=index_path)
    run(output)
    verify_run(output)


def compare_native(directory, oracle, output):
    verification = read(directory/'verification.json')
    assert verification['protocol_correctness_passed']
    matches = list((directory/'runtime-results').glob('run-*/results.json'))
    assert len(matches) == 1
    actual = read(matches[0])
    checks = []
    for r, (expected, record, after, metric) in enumerate(zip(oracle['rounds'], actual['records'], actual['models'][1:], actual['metrics'][1:], strict=True), 1):
        result = record['result_certificate']['body']['result']
        assert record['manifest']['presence'] == [1]*4
        assert result['status'] == expected['status']
        if result['status'] == 'ok':
            assert result['count'] == expected['count']
            assert hashlib.sha256(np.asarray(result['sum'], dtype='<i8').tobytes()).hexdigest() == expected['sum_sha256']
        else:
            assert result == {'status': 'abort'}
        assert vector_hash(np.asarray(after, dtype=np.float64)) == expected['model_sha256']
        assert metric['accuracy'] == expected['metrics']['accuracy']
        # Evaluators use different batching/accumulation; verify each native loss
        # exactly against its own independent evaluator, plus close to oracle.
        assert abs(metric['loss']-expected['metrics']['loss']) < 1e-7
        for slot in range(4):
            key = f'{oracle["seed"]}-strong-{r}-{slot}-{expected["input_model_sha256"]}'
            with np.load(output/'trusted-private-cache'/f'{key}.npz', allow_pickle=False) as saved:
                q = saved['q']
            audit = read(directory/f'clients/C{slot}/audit/round-{r}.json')
            assert np.array_equal(q, np.asarray(audit['update'], dtype=np.int64))
        checks.append({'round': r, 'status': result['status'], 'sum_or_abort_exact': True,
                       'count_or_abort_exact': True, 'model_exact': True, 'accuracy_exact': True,
                       'individual_inputs_exact': 4, 'loss_difference': abs(metric['loss']-expected['metrics']['loss'])})
    native_comm = verification['communication']['native']
    return {'seed': oracle['seed'], 'distribution': 'strong', 'radius': oracle['radius'],
            'checks': checks, 'compile_invocations': verification['compile_invocations'],
            'compile_seconds': verification['compile_seconds'], 'wall_seconds': verification['wall_seconds'],
            'setup_sent_bytes': native_comm['setup_sent_bytes'],
            'round_sent_bytes': [r['sent_bytes'] for r in native_comm['rounds']],
            'counter_reconciled': native_comm['reconciled'],
            'verification_sha256': sha(directory/'verification.json'),
            'scope': verification['scope']}


def plot(public, summary, rows, selected):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 3, figsize=(14, 4), sharey=True)
    for ax, distribution in zip(axes, DISTRIBUTIONS):
        for row in [r for r in summary if r['distribution'] == distribution]:
            ax.plot(row['mean_curve_percent'], marker='o', label='No filter' if row['radius'] is None else f'R={row["radius"]:g}')
        ax.set_title(distribution); ax.set_xlabel('Round'); ax.grid(alpha=.25); ax.legend(fontsize=8)
    axes[0].set_ylabel('Test accuracy (%)')
    fig.suptitle('Full FMNIST / LeNet5 / normal clients / static L2 thresholds')
    fig.tight_layout(); fig.savefig(public/'accuracy.png', dpi=180); plt.close(fig)
    fig, axes = plt.subplots(1, 3, figsize=(14, 4), sharey=True)
    for ax, distribution in zip(axes, DISTRIBUTIONS):
        for radius in RADII:
            values = [v for r in rows if r['distribution'] == distribution and r['radius'] == radius for row in r['rounds'] for v in row['l2']]
            ax.scatter([radius]*len(values), values, alpha=.3, s=12)
        ax.plot(RADII, RADII, '--', color='black', label='L2 threshold')
        ax.set_title(distribution); ax.set_xlabel('Static L2 radius'); ax.set_xticks(RADII); ax.grid(alpha=.25)
    axes[0].set_ylabel('Normal update L2 (quantized)')
    fig.tight_layout(); fig.savefig(public/'norms.png', dpi=180); plt.close(fig)


def markdown(report, body):
    public = report.with_suffix('')
    rows = body['summary']
    names = {'iid': 'IID', 'moderate': '중간 Non-IID', 'strong': '강한 Non-IID'}
    text = ['# 정상 클라이언트의 Non-IID·고정 L2 threshold 실험', '',
            '실제 수행 결과. 공격 없이 정상 SGD 업데이트만 제출하고, threshold로 인한 제외와 학습 변화를 비교했다.', '',
            '## 설정과 분할', '',
            '- Full Fashion-MNIST train 60,000 / test 10,000, LeNet5 61,706개 파라미터, 클라이언트 4명·각 15,000개.',
            '- Local epoch 1, batch 64, CPU SGD lr .01 / momentum .9 / weight decay .0005. 각 local 호출에서 optimizer를 새로 만든다.',
            '- 탐색: seed 42·43·44, 5라운드, 분포 3개 × 무필터/반경 1·2.5·5·10 = **45회·225라운드**.',
            '- S=10,000, Q=65,536, 좌표 B=20,000(실수 2), 최소 통과 2. norm 제곱 기준은 T=(SR)². 모든 정책은 세션 시작 전에 고정.',
            '- 중간/강한 분할: Dirichlet α=.5/.1의 클래스 선호를 행·열 합에 맞춰 조정한 **동일 크기 제약 label skew**. 일반적인 무제약 Dirichlet 분할과 다르다.',
            '- 모든 학습 행을 중복 없이 한 번 배정했다. 아래 실제 클래스 개수와 entropy를 확인해야 α만으로 분포를 해석하지 않는다.',
            '- 동일 seed/분포에서 초기 모델과 샤드를 맞추고, 집계가 달라진 뒤에는 각 조건의 현재 모델에서 다시 학습한다. Cache는 seed·분포·round·slot·현재 모델 hash로 구분한다.',
            '- count<2인 라운드는 인증된 abort로 처리해 모델을 유지하고 다음 라운드로 진행한다. 이 경우를 삭제하거나 성공 실행으로 바꾸지 않았다.', '',
            '## 5라운드 결과', '',
            '평균 ±는 3개 seed의 표본 표준편차(%p)이며 신뢰구간이 아니다. 제외율 분모는 조건당 정상 제출 60건이다.', '',
            '| 분포 | L2 반경 | seed별 정확도(%) | 평균 ± 표준편차 | 정상 제외 | abort 라운드 |',
            '|---|---|---|---|---|---|']
    for row in rows:
        text.append(f'| {names[row["distribution"]]} | {"무필터" if row["radius"] is None else row["radius"]} | '+
                    ' / '.join(f'{v:.2f}' for v in row['final_accuracy_percent'])+
                    f' | {row["mean_accuracy_percent"]:.2f} ± {row["std_percentage_points"]:.2f} | {row["rejected"]}/{row["submissions"]} | {row["abort_rounds"]}/15 |')
    text += ['', f'![정확도]({public.name}/accuracy.png)', '', f'![정상 업데이트 norm]({public.name}/norms.png)', '',
             '## 클라이언트별 제외와 검사 원인', '',
             '| 분포 | 반경 | C0 / C1 / C2 / C3 제외(각 15건) | 좌표 초과 | L2 초과 |', '|---|---|---|---|---|']
    for row in rows:
        if row['radius'] is not None:
            text.append(f'| {names[row["distribution"]]} | {row["radius"]} | '+ ' / '.join(map(str, row['rejected_per_client']))+
                        f' | {row["coordinate_failures"]} | {row["norm_failures"]} |')
    text += ['', '좌표/L2 초과는 겹칠 수 있다. C 번호는 seed별 재분할되는 슬롯으로 동일 사람을 의미하지 않는다. 개별 norm/판정은 trusted 연구용 audit 지표이며 운영 서버에 새로 공개한 정보가 아니다.', '',
             '## 실제 데이터 분포', '', '| seed | 분포 | 평균 클래스 entropy(bits) |', '|---|---|---:|']
    for entry in body['partitions']:
        text.append(f'| {entry["seed"]} | {names[entry["distribution"]]} | {entry["mean_class_entropy_bits"]:.4f} |')
    for entry in body['partitions']:
        if entry['seed'] not in body['configuration']['seeds']:
            continue
        text += ['', f'### seed {entry["seed"]} · {names[entry["distribution"]]}', '',
                 '| client | class 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |', '|---|'+'---:|'*10]
        for slot, counts in enumerate(entry['class_counts']):
            text.append(f'| C{slot} | '+' | '.join(map(str, counts))+' |')
    selection = body['selection']
    text += ['', '## 선택과 새로운 seed 확인', '',
             f'강한 Non-IID 탐색 결과에서 최종 정확도 평균, 적은 제외 수, 기존 반경 5 우선, 작은 반경 순으로 선정했다. 선택된 반경은 **{selection["selected_radius"]}**다.',
             '테스트 정확도를 사용한 선택이므로 탐색 결과다. 새 seed 45·46·47에서 무필터와 선택 반경을 10라운드 비교했다. 데이터 분할·초기화의 반복 확인이며, 같은 FMNIST test set을 다시 사용해 독립 holdout 평가를 대신하지 않는다.', '',
             '| 강한 Non-IID | seed별 최종 정확도(%) | 평균 ± 표준편차 | 정상 제외 | abort |', '|---|---|---|---|---|']
    for row in body['confirmation_summary']:
        text.append(f'| {"무필터" if row["radius"] is None else "R="+str(row["radius"])} | '+
                    ' / '.join(f'{v:.2f}' for v in row['final_accuracy_percent'])+
                    f' | {row["mean_accuracy_percent"]:.2f} ± {row["std_percentage_points"]:.2f} | {row["rejected"]}/{row["submissions"]} | {row["abort_rounds"]}/30 |')
    text += ['', '## 실제 Flower·Rep4 검증', '',
             '강한 Non-IID의 현재 반경 5와 선택 반경을 실제 MPC로 실행했다. 동일 반경이면 중복 실행을 생략한다. 정상 학습 자체를 바꾸거나 synthetic 업데이트로 대체하지 않았다.', '',
             '| seed | 반경 | 검증 라운드 | 개인 입력 | SUM/count 또는 abort | 모델·accuracy |', '|---|---|---:|---|---|---|']
    for run in body['native_runs']:
        text.append(f'| {run["seed"]} | {run["radius"]} | {len(run["checks"])} | 전체 좌표 정확히 일치 | 전체 정확히 일치 | 전체 정확히 일치 |')
    text += ['', 'Native 검증기는 클라이언트 재학습·샤드 hash·인증서·정수 합·모델을 독립 확인했다. 추가로 평문 cache의 개별 입력과 native client audit을 좌표별 비교했다. 각 loss는 native evaluator로 재검증했으며, 평문 evaluator와의 차이는 JSON에 기록했다.', '',
             '## 초기 설정과 라운드 비용', '',
             '네 aggregator의 추적된 native Player payload 송신 합계. live preprocessing 포함, TLS/TCP/framing·미추적 exchange·Flower/RPC 제외. 전체 시스템 통신량이 아니다.', '',
             '| seed | 반경 | setup bytes | round 1~5 MB(10⁶ bytes) | ServerApp wall 초 | compile 횟수 |', '|---|---|---:|---|---:|---:|']
    for run in body['native_runs']:
        text.append(f'| {run["seed"]} | {run["radius"]} | {run["setup_sent_bytes"]:,} | '+
                    ' / '.join(f'{v/1e6:.2f}' for v in run['round_sent_bytes'])+
                    f' | {run["wall_seconds"]:.2f} | {run["compile_invocations"]} |')
    text += ['', 'Threshold가 다른 정책은 별도 회로/cache key를 사용한다. 동일 정책의 반복은 compile cache를 사용하며 라운드별 재컴파일·seed 재등록은 없다. wall은 학습·수집·MPC·인증을 포함하며 평문 cache 실행과 공정한 속도 비율을 뜻하지 않는다.', '',
             '## 해석과 한계', '',
             '- 정상 SGD 업데이트라도 정적 norm 한도를 넘으면 제외된다. 이를 공격 탐지율로 표현하지 않는다.',
             '- 5라운드 결과만으로 수렴 성능을 단정하지 않는다. 새 seed의 10라운드 결과도 이 설정의 짧은 학습 확인이다.',
             '- 제외율이 낮은 큰 threshold가 poisoning 방어에 더 좋다는 뜻은 아니다. 공격/보안 허용 범위를 결정할 근거는 별도다.',
             '- 같은 WSL UID의 trusted Flower Simulation + 실제 active Rep4. 네 독립 운영자의 물리적 배포/공모 시험·DP·전체 프라이버시 증명이 아니다.',
             '- Client 4명, LeNet5, FMNIST, 고정 학습률과 동일 크기 분할의 결과다. 모델·local epoch·분포 변경 시 같은 norm 분포를 가정하지 않는다.',
             '- Seed·개인 키·raw 업데이트·학습 파일은 private .cache에만 보관한다. 공개 JSON에는 연구 통계/hash/equality/counter만 내보낸다.', '',
             '## 재현', '', '```bash', '.venv/bin/python -u -m experiments.run_noniid_threshold \\',
             '  --output .cache/new-noniid-threshold \\',
             '  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1 \\',
             '  --report docs/reproduction/new-noniid-threshold.md', '```', '',
             f'[전체 결과 JSON]({public.name}/results.json), [공개 파일·소스 hash]({public.name}/manifest.json). Hub 게시·계정 설정은 하지 않았다.']
    report.write_text('\n'.join(text)+'\n')


def export(output, report, rows, confirmation, native_runs, selection):
    public = report.with_suffix('')
    public.mkdir(parents=True, exist_ok=True)
    partitions = read(output/'partition-summary.json')
    body = {'completed': True, 'configuration': read(output/'configuration.json'),
            'partitions': partitions, 'summary': summarized(rows), 'conditions': rows,
            'selection': selection, 'confirmation_summary': summarized(confirmation),
            'confirmation_conditions': confirmation, 'native_runs': native_runs,
            'native_rounds': sum(len(r['checks']) for r in native_runs),
            'native_individual_input_comparisons': sum(4*len(r['checks']) for r in native_runs)}
    write(public/'results.json', body)
    plot(public, body['summary'], rows, selection)
    markdown(report, body)
    write(public/'manifest.json', {'files': {p.name: sha(p) for p in public.iterdir() if p.is_file() and p.name != 'manifest.json'},
                                   'report_sha256': sha(report), 'source_sha256': body['configuration']['source_sha256']})
    print('NONIID_THRESHOLD_COMPLETED', report, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mp-spdz-dir', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--native-worker', action='store_true')
    parser.add_argument('--seed', type=int)
    parser.add_argument('--radius', type=float)
    args = parser.parse_args()
    os.environ.update(PATH=str(ROOT/'.venv/bin')+':/usr/local/bin:/usr/bin:/bin',
                      OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', MKL_NUM_THREADS='1', RAY_USAGE_STATS_ENABLED='0')
    output = args.output.resolve()
    installation = args.mp_spdz_dir.resolve()
    if args.native_worker:
        native(output, installation, args.seed, args.radius, 5)
        return
    if args.report is None:
        parser.error('--report required')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    for folder in ('oracle', 'partitions', 'trusted-private-cache'):
        (output/folder).mkdir(exist_ok=True, mode=0o700)
    data = read_dataset(ROOT/'.cache/fashion-mnist/FashionMNIST/raw')
    config = {'seeds': [42, 43, 44], 'confirmation_seeds': [45, 46, 47], 'rounds': 5,
              'confirmation_rounds': 10, 'radii': list(RADII), 'distributions': DISTRIBUTIONS,
              'training': TRAINING, 'native_backend': str(installation),
              'source_sha256': {p: sha(ROOT/p) for p in SOURCES},
              'versions': {p: importlib.metadata.version(p) for p in ('numpy', 'torch', 'flwr', 'ray')},
              'data_sha256': {k: hashlib.sha256(v.tobytes()).hexdigest() for k, v in data.items()},
              'scope': 'trusted local experimental harness; four-party actual active Rep4; no operator isolation'}
    if (output/'configuration.json').exists():
        assert read(output/'configuration.json') == config, 'source/configuration changed: use fresh output'
    else:
        write(output/'configuration.json', config)
    partitions = []
    for seed in config['seeds']+config['confirmation_seeds']:
        distributions = DISTRIBUTIONS if seed in config['seeds'] else {'strong': .1}
        for distribution, alpha in distributions.items():
            indices = balanced_partition(data['train_y'], seed, alpha)
            path = output/'partitions'/f'{seed}-{distribution}.npy'
            if path.exists():
                assert np.array_equal(indices, np.load(path, allow_pickle=False))
            else:
                np.save(path, indices); path.chmod(0o600)
            partitions.append({'seed': seed, 'distribution': distribution, 'alpha': alpha, **partition_info(data['train_y'], indices)})
    write(output/'partition-summary.json', partitions)
    rows = []
    for seed in config['seeds']:
        for distribution in DISTRIBUTIONS:
            for radius in (None,)+RADII:
                rows.append(condition(output, data, seed, distribution, radius, 5))
    selection = choose(summarized(rows))
    write(output/'selection.json', selection)
    print('SELECTION', selection, flush=True)
    confirmation = []
    for seed in config['confirmation_seeds']:
        for radius in (None, selection['selected_radius']):
            confirmation.append(condition(output, data, seed, 'strong', radius, 10))
    native_runs = []
    for radius in selection['native_radii']:
        for seed in config['seeds']:
            directory = output/f'native-seed-{seed}-strong-R{radius}'
            if not (directory/'verification.json').exists():
                if directory.exists():
                    raise RuntimeError('unfinished native session: preserve artifacts, start fresh output/session')
                command = [sys.executable, '-u', '-m', 'experiments.run_noniid_threshold', '--native-worker',
                           '--output', str(directory), '--mp-spdz-dir', str(installation), '--seed', str(seed), '--radius', str(radius)]
                print('START_NATIVE', seed, radius, flush=True)
                with directory.with_suffix('.log').open('x') as log:
                    subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
            oracle = next(r for r in rows if r['seed'] == seed and r['distribution'] == 'strong' and r['radius'] == radius)
            native_runs.append(compare_native(directory, oracle, output))
            print('VERIFIED_NATIVE', seed, radius, flush=True)
    assert config['source_sha256'] == {p: sha(ROOT/p) for p in SOURCES}
    export(output, args.report.resolve(), rows, confirmation, native_runs, selection)


if __name__ == '__main__':
    main()

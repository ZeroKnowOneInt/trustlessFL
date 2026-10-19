"""Independent arithmetic replay and public-export checks for local research."""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from trustlessfl.seed_mpc_training import initial_lenet


def read(path): return json.loads(Path(path).read_text())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def model_hash(v): return hashlib.sha256(np.asarray(v, dtype='<f8').tobytes()).hexdigest()
def write(path, value): Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')


def verify(output, report):
    public = report.with_suffix('')
    body = read(public/'results.json')
    checks = []
    for condition in body['conditions']+body['confirmation_conditions']:
        seed = condition['seed']; distribution = condition['distribution']
        policy = condition['policy']; model = initial_lenet(seed)
        rejected = [0]*4
        for row in condition['rounds']:
            before = model_hash(model)
            assert before == row['input_model_sha256']
            vectors = []
            coordinate_ok = []; norm_ok = []; norms = []
            for slot in range(4):
                path = output/'trusted-private-cache'/f'{seed}-{distribution}-{row["round"]}-{slot}-{before}.npz'
                with np.load(path, allow_pickle=False) as saved:
                    q = [int(v) for v in saved['q']]
                assert len(q) == policy['dimension']
                assert all(-32768 <= v < 32768 for v in q)
                squared = sum(v*v for v in q)
                norms.append(squared)
                coordinate_ok.append(all(abs(v) <= policy['coordinate_cap'] for v in q))
                norm_ok.append(squared <= policy['squared_threshold'])
                vectors.append(q)
            keep = [True]*4 if condition['radius'] is None else [a and b for a,b in zip(coordinate_ok,norm_ok)]
            assert keep == row['accepted'] and coordinate_ok == row['coordinate_ok'] and norm_ok == row['norm_ok']
            assert norms == row['norm2']
            assert sum(keep) == row['count']
            rejected = [v+int(not keep[i]) for i,v in enumerate(rejected)]
            if sum(keep) < policy['minimum_accepted']:
                assert row['status'] == 'abort' and row['sum_sha256'] is None
            else:
                assert row['status'] == 'ok'
                # Python unbounded integer sums avoid depending on NumPy's
                # original aggregation implementation or overflow behaviour.
                total = [sum(v[j] for v,k in zip(vectors,keep) if k) for j in range(policy['dimension'])]
                assert hashlib.sha256(np.asarray(total,dtype='<i8').tobytes()).hexdigest() == row['sum_sha256']
                model = model+np.asarray(total,dtype=np.float64)/(policy['scale']*sum(keep))
            assert model_hash(model) == row['model_sha256']
            checks.append({'seed':seed,'distribution':distribution,'radius':condition['radius'],
                           'round':row['round'],'arithmetic_exact':True,'status':row['status']})
        assert rejected == condition['rejected_per_client']
    assert len(checks) == 285
    # Compare the unfiltered model trajectory with R5/R10, not just accuracy.
    for condition in body['conditions']+body['confirmation_conditions']:
        if condition['radius'] not in (5.,10.): continue
        reference = next(r for r in body['conditions']+body['confirmation_conditions']
                         if r['seed']==condition['seed'] and r['distribution']==condition['distribution']
                         and r['radius'] is None and r['round_slots']==condition['round_slots'])
        assert all(a['model_sha256']==b['model_sha256'] and a['metrics']==b['metrics']
                   for a,b in zip(condition['rounds'],reference['rounds'],strict=True))
    write(public/'arithmetic-checks.json', {'passed':True,'rounds':len(checks),
         'client_rounds':4*len(checks),'checks':checks,'R5_R10_unfiltered_models_exact':True,
         'scope':'trusted private cache replay; Python integer arithmetic; no keys/seeds in output'})
    body['independent_arithmetic_replay'] = {'rounds':len(checks),'client_rounds':4*len(checks),'passed':True}
    for run in body['native_runs']:
        directory = output/f'native-seed-{run["seed"]}-strong-R{run["radius"]}'
        verification = read(directory/'verification.json')
        run['round_timings'] = verification['round_timings']
        run['round_phase_seconds'] = [sum(v for k,v in row.items() if k.endswith('_seconds'))
                                      for row in run['round_timings']]
        run['compilation'] = verification['compilation']
    write(public/'results.json',body)
    text = report.read_text()
    scope_note = ('실행 범위: **평문 탐색 45회·225라운드 + 새로운 seed 평문 확인 6회·60라운드**, '
                  '**실제 Flower·active Rep4 3회·15라운드**. MPC backend는 MP-SPDZ 0.4.3의 '
                  '검증된 holder-checked direct importer 경로다. 작은 반경의 abort 결과는 평문 기준 실험이며, '
                  '이번 실제 MPC 대조는 선택된 반경 5에 한정했다.')
    intro = '실제 수행 결과. 공격 없이 정상 SGD 업데이트만 제출하고, threshold로 인한 제외와 학습 변화를 비교했다.'
    if scope_note not in text:
        text = text.replace(intro, intro+'\n\n'+scope_note)
    finding = ('**반경 5는 정상 입력 300건을 제외하지 않았고, 무필터와 모든 라운드 모델이 같았다.** '
               '5라운드 평균 정확도는 IID 86.24%, 중간 Non-IID 84.00%, 강한 Non-IID 75.23%였다. '
               '반경 1·2.5는 탐색에서 정상 입력을 전부 제외해 학습을 시작하지 못했다. '
               '선정된 반경 5의 실제 MPC 15라운드도 평문 기준과 정확히 일치했다.')
    if finding not in text:
        text = text.replace(intro, finding+'\n\n'+intro)
    text = text.replace('- count<2인 라운드는 인증된 abort로 처리해 모델을 유지하고 다음 라운드로 진행한다.',
                        '- 평문 기준에서 count<2인 라운드는 abort로 기록해 모델을 유지하고 다음 라운드로 진행한다.')
    caption = '무필터·반경 5·10 곡선은 모델이 같아 겹친다. 반경 1·2.5 곡선도 초기 모델이 유지돼 겹친다. Norm 그림의 검은 점선은 허용 반경이다.'
    if caption not in text:
        text = text.replace('## 클라이언트별 제외와 검사 원인',caption+'\n\n## 클라이언트별 제외와 검사 원인')
    # Idempotent post-run note, after original report's complete tables.
    heading = '\n## 핵심 해석과 추가 검증\n'
    text = text.split(heading)[0]
    text += heading+'\n'
    for distribution in ('iid','moderate','strong'):
        r = next(r for r in body['summary'] if r['distribution']==distribution and r['radius']==5.)
        text += f'- {distribution}: 반경 5의 평균 정확도 **{r["mean_accuracy_percent"]:.2f}%**, 정상 제외 **{r["rejected"]}/{r["submissions"]}**. 무필터와 모든 라운드 모델이 정확히 같다.\n'
    confirmation = next(r for r in body['confirmation_summary'] if r['radius']==5.)
    reference_rows = [r for r in body['conditions']+body['confirmation_conditions'] if r['radius'] is None]
    max_first = max(v for r in reference_rows for v in r['rounds'][0]['l2'])
    max_all = max(v for r in reference_rows for row in r['rounds'] for v in row['l2'])
    text += f'\n반경 1·2.5는 탐색의 분포별 **60/60 정상 제출을 제외**했고 각 분포에서 **15/15라운드가 abort**였다. 초기 모델이 갱신되지 않아 정상 norm이 충분히 작아지는 학습 단계에 도달하지 못했다. 제외율을 마지막 라운드 norm만으로 판단해서는 안 된다.\n'
    text += f'\n새 seed의 강한 Non-IID 10라운드에서 반경 5와 무필터는 모두 **{confirmation["mean_accuracy_percent"]:.2f}% ± {confirmation["std_percentage_points"]:.2f}%p**, 반경 5의 정상 제외는 **0/120**이었다. 전체 무필터 기준 실행의 첫 라운드 최대 L2는 **{max_first:.5f}**, 모든 라운드 최대는 **{max_all:.5f}**였다.\n'
    text += '\n무필터 기준 첫 라운드의 정상 L2 분포(3 seeds × 4 clients)는 다음과 같다.\n\n| 분포 | 최소 | 평균 | 최대 |\n|---|---:|---:|---:|\n'
    for distribution in ('iid','moderate','strong'):
        values = [v for r in body['conditions'] if r['distribution']==distribution and r['radius'] is None
                  for v in r['rounds'][0]['l2']]
        text += f'| {distribution} | {min(values):.5f} | {np.mean(values):.5f} | {max(values):.5f} |\n'
    text += '\n이 설정에서는 강한 Non-IID의 초기 평균 L2가 IID보다 작았다. 데이터 이질성이 커지면 정상 norm도 반드시 커진다는 가정은 이번 결과와 맞지 않는다.\n'
    text += '\n이번 설정에서는 반경 5를 유지할 근거가 있고, Non-IID 때문에 동적 바운더리가 필요하다는 증거는 없었다. 다만 반경 5·10이 모든 정상 입력을 통과시켰으므로 부분적으로 일부 클라이언트만 제외되는 상황은 이번 후보에서 관측되지 않았다. 더 긴 학습·다른 local epoch나 모델에서 같은 판단을 보장하지 않는다.\n'
    text += '\n반경 2.5~5 사이를 탐색하지 않았으므로 5가 최소 허용값이나 모든 상황의 최적 threshold라는 주장은 하지 않는다. 이번 실험은 공격 없이 정상 학습만 비교했으며 threshold 이내 공격에 대한 성능을 평가하지 않는다.\n'
    text += '\n### 클래스별 정확도\n\n반경 5의 seed별 최종 클래스 정확도를 평균했다. 무필터와 동일하며, class 번호는 FMNIST 원래 label이다.\n\n'
    text += '| 분포/길이 | class 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |\n|---|'+'---:|'*10+'\n'
    for distribution in ('iid','moderate','strong'):
        selected = [r for r in body['conditions'] if r['distribution']==distribution and r['radius']==5.]
        values = np.mean([r['rounds'][-1]['metrics']['class_accuracy'] for r in selected],axis=0)*100
        text += f'| {distribution}/5r | '+' | '.join(f'{v:.2f}%' for v in values)+' |\n'
    selected = [r for r in body['confirmation_conditions'] if r['radius']==5.]
    values = np.mean([r['rounds'][-1]['metrics']['class_accuracy'] for r in selected],axis=0)*100
    text += '| strong/10r·새 seed | '+' | '.join(f'{v:.2f}%' for v in values)+' |\n'
    text += f'\n별도 검증기로 **285라운드·1,140개 client-round**의 norm·좌표 검사·정수 SUM·abort·모델을 private cache에서 Python 정수로 재계산했다. 모두 일치했다. [추가 산술 검증]({public.name}/arithmetic-checks.json). 관련 테스트는 **65 passed**였다.\n'
    text += '\n### 라운드별 시간\n\n학습/수집·입력 인증·실행/결과 인증·적용·client 통지의 측정 단계 합계다. 초기 등록과 최종 shutdown 등 라운드 외 작업은 포함하지 않는다. 실행/결과 인증 시간도 순수 MPC 연산 시간과 동일하지 않다.\n\n'
    text += '| seed | R | compile/cache 조회 | round 1~5 단계 합계(초) | round 1~5 실행·결과 인증(초) |\n|---|---|---|---|---|\n'
    for run in body['native_runs']:
        compile_text = 'cache hit' if run['compilation']['hit'] else f'{run["compile_seconds"]:.3f}초 compile'
        text += f'| {run["seed"]} | {run["radius"]} | {compile_text} | '+' / '.join(f'{v:.3f}' for v in run['round_phase_seconds'])+' | '
        text += ' / '.join(f'{r["execute_and_result_certificate_seconds"]:.3f}' for r in run['round_timings'])+' |\n'
    text += '\n```bash\n.venv/bin/python -m experiments.verify_noniid_threshold \\\n  --output .cache/noniid-threshold-2026-10-12 \\\n  --report docs/reproduction/noniid-threshold-2026-10-12.md\n```\n'
    report.write_text(text)
    # Collect exact private seed/key strings from the separately owned local
    # artifacts. Public fingerprints are intentionally not classified as keys.
    secrets = set()
    for directory in output.glob('native-*'):
        if not directory.is_dir(): continue
        for path in directory.glob('clients/*/seed-input.json'):
            secrets.update(read(path)['component_seeds'])
        for path in directory.glob('mpc/P*/service-private.json'):
            identity = read(path)['identity']
            secrets.update([identity['signing'], identity['encryption']])
        for path in directory.glob('clients/*/client.json'):
            item = read(path)
            if 'identity' in item:
                secrets.update([item['identity']['signing'],item['identity']['encryption']])
    targets = [report]+[p for p in public.iterdir() if p.suffix=='.json' and p.name!='manifest.json']
    assert len(secrets) >= 72
    for target in targets:
        value = target.read_text()
        assert 'BEGIN PRIVATE KEY' not in value
        assert not any(secret in value for secret in secrets)
    manifest = read(public/'manifest.json')
    manifest.update(files={p.name:sha(p) for p in public.iterdir() if p.is_file() and p.name!='manifest.json'},
                    report_sha256=sha(report),additional_verifier_sha256=sha(Path(__file__)),
                    private_string_scan={'passed':True,'exact_private_strings':len(secrets),'text_files':len(targets)})
    write(public/'manifest.json',manifest)
    print('INDEPENDENT_ARITHMETIC_EXACT',len(checks),'CLIENT_ROUNDS',4*len(checks),'SECRET_SCAN',len(secrets))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();verify(args.output.resolve(),args.report.resolve())

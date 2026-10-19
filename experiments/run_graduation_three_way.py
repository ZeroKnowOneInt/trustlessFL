"""Paired full-FMNIST experiment: mean / plain bound / actual Flower Rep4.

This is a trusted research harness. Private update audits stay in local .cache;
public exports contain metrics/hashes/counters only. Never a production fallback.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import numpy as np

ROOT=Path(__file__).resolve().parents[1]
CASES=('clean','norm-overflow')
SOURCES=('experiments/run_graduation_three_way.py','experiments/run_seed_mpc_poisoning.py',
         'experiments/run_seed_mpc_flower.py','trustlessfl/seed_mpc_poisoning_fixture.py',
         'trustlessfl/seed_mpc_training.py','trustlessfl/seed_mpc_policy.py')


def read(path): return json.loads(Path(path).read_text())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):
    path=Path(path); temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');temporary.replace(path)


def native(output,installation,seed,case,rounds):
    from experiments.run_seed_mpc_flower import stage,run,verify_run
    stage(output,installation,mode='fmnist-lenet5',seed=seed,rounds=rounds,timeout=1200,
          snapshot_version=2,collection_window_ms=600000,communication_meter=True,
          test_audit=True,test_poisoning=case,chunk_blocks=64,component_input='holder-checked-direct-v1',
          compile_cache=ROOT/'.cache/graduation-three-way-circuits')
    run(output);verify_run(output)


def export(output,report,seeds,rounds):
    from experiments.run_seed_mpc_poisoning import POLICY,vector_hash
    public=report.with_suffix('');public.mkdir(parents=True,exist_ok=True)
    comparisons=[];native_runs=[];plain=[]
    for seed in seeds:
        for case in CASES:
            oracle=read(output/'oracle'/f'seed-{seed}-{case}-m1.json')
            assert oracle['status']=='completed' and len(oracle['rounds'])==rounds
            plain.append(oracle)
            directory=output/f'native-seed-{seed}-{case}'
            verification=read(directory/'verification.json')
            assert verification['passed'] and verification['learning_workload_completed']
            results=list((directory/'runtime-results').glob('run-*/results.json'));assert len(results)==1
            result=read(results[0]);checks=[]
            for r,(row,decision,model,metric) in enumerate(zip(oracle['rounds'],result['records'],
                    result['models'][1:],result['metrics'][1:],strict=True),1):
                expected=row['variants']['static-filter'];actual=decision['result_certificate']['body']['result']
                assert actual['status']=='ok' and decision['manifest']['presence']==[1]*4
                assert actual['count']==expected['accepted_count']
                assert hashlib.sha256(np.asarray(actual['sum'],dtype='<i8').tobytes()).hexdigest()==expected['sum_sha256']
                assert vector_hash(np.asarray(model,dtype=np.float64))==expected['model_sha256']
                assert metric['accuracy']==expected['metrics']['accuracy']
                assert metric['loss']==expected['metrics']['loss']
                checks.append({'round':r,'sum_exact':True,'count_exact':True,'model_exact':True,
                    'accuracy_exact':True,'loss_exact':True,'accepted':actual['count']})
            comparisons.append({'seed':seed,'case':case,'rounds':checks})
            comm=verification['communication']['native']
            native_runs.append({'seed':seed,'case':case,'metrics':result['metrics'],
                'compile_invocations':verification['compile_invocations'],'compile_seconds':verification['compile_seconds'],
                'serverapp_wall_seconds':verification['wall_seconds'],'round_timings':verification['round_timings'],
                'native_setup_sent_bytes':comm['setup_sent_bytes'],
                'native_round_sent_bytes':[r['sent_bytes'] for r in comm['rounds']],
                'native_total_sent_bytes':comm['total_sent_bytes'],'counter_reconciled':comm['reconciled'],
                'scope':verification['scope'],'verification_sha256':sha(directory/'verification.json')})
    summary=[]
    for case in CASES:
        for variant in ('mean','static-filter','private-mpc'):
            rows=[r for r in plain if r['case']==case]
            values=[100*r['rounds'][-1]['variants']['mean' if variant=='mean' else 'static-filter']['metrics']['accuracy'] for r in rows]
            curves=[]
            honest_rejected=malicious_rejected=0
            for r in rows:
                name='mean' if variant=='mean' else 'static-filter'
                curves.append([100*r['initial_metrics']['accuracy']]+[100*v['variants'][name]['metrics']['accuracy'] for v in r['rounds']])
                if variant!='mean':
                    honest_rejected+=sum(v['variants'][name]['honest_rejected_static'] for v in r['rounds'])
                    if case!='clean':malicious_rejected+=sum(1-v['variants'][name]['malicious_passed_static'] for v in r['rounds'])
            summary.append({'case':case,'variant':variant,'seeds':seeds,'final_accuracy_percent':values,
                'mean_final_accuracy_percent':float(np.mean(values)),
                'sample_std_percentage_points':float(np.std(values,ddof=1)) if len(values)>1 else None,
                'mean_accuracy_curve_percent':np.mean(curves,axis=0).tolist(),
                'honest_rejected':honest_rejected,'honest_submissions':len(seeds)*rounds*(4 if case=='clean' else 3),
                'malicious_rejected':malicious_rejected,'malicious_submissions':0 if case=='clean' else len(seeds)*rounds,
                'private_mpc_values_independently_compared':variant=='private-mpc'})
    exported={'completed':True,'policy':asdict(POLICY),'seeds':seeds,'rounds':rounds,
        'cases':list(CASES),'summaries':summary,'plain_reports':plain,'native_runs':native_runs,
        'exact_comparisons':comparisons,'configuration':read(output/'configuration.json'),
        'scope':'full real FMNIST; actual Flower Simulation and Rep4 on one WSL UID; trusted private audits only for post-run verification; no independent operator isolation/privacy proof'}
    write(public/'results.json',exported)
    plot(public,summary)
    hashes={str(f.relative_to(public)):sha(f) for f in public.iterdir() if f.is_file() and f.name!='manifest.json'}
    write(public/'manifest.json',{'files':hashes,'source_sha256':read(output/'configuration.json')['source_sha256'],
        'scope':'public metrics/hash/counter export; no keys/seeds/private inputs/model audit files'})
    markdown(report,summary,native_runs,comparisons,rounds,seeds,public)


def plot(public,summary):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    labels={'mean':'No filter','static-filter':'Plain bound','private-mpc':'Private MPC'}
    colors={'mean':'#dc2626','static-filter':'#2563eb','private-mpc':'#059669'}
    fig,axes=plt.subplots(1,2,figsize=(11,4.3),sharey=True)
    for ax,case in zip(axes,CASES,strict=True):
        for row in [r for r in summary if r['case']==case]:
            variant=row['variant'];curve=row['mean_accuracy_curve_percent']
            ax.plot(range(len(curve)),curve,color=colors[variant],label=labels[variant],
                    marker='o' if variant!='private-mpc' else 'x',linestyle='-' if variant!='private-mpc' else '--',
                    linewidth=2,markersize=6)
        ax.set_title('Clean' if case=='clean' else 'Coordinate-valid L2 overflow');ax.set_xlabel('Round')
        ax.grid(alpha=.25);ax.legend(fontsize=9)
    axes[0].set_ylabel('Test accuracy (%)');fig.suptitle('Full Fashion-MNIST / LeNet5: paired three-way comparison')
    fig.tight_layout();fig.savefig(public/'accuracy.png',dpi=180);plt.close(fig)


def markdown(report,summary,native_runs,comparisons,rounds,seeds,public):
    def row(case,variant):return next(r for r in summary if r['case']==case and r['variant']==variant)
    labels={'mean':'무필터 양자화 평균','static-filter':'평문 동일 bound 검사','private-mpc':'비공개 Flower·MPC bound 검사'}
    text=['# 졸업작품: 무필터·평문 bound·비공개 MPC 비교 실험 결과','',
        '2026-10-12, WSL Ubuntu-24.04, `work/aion-private-bound-no-wrap`. 실제 수행 완료한 결과만 기록한다.','',
        '## 조건과 비교 방법','',
        f'- Full LeNet5: **61,706개 파라미터**, Fashion-MNIST train **60,000** / test **10,000**.',
        f'- Client **4명**, IID 각 **15,000개**, local epoch 1, batch 64, SGD lr .01 / momentum .9 / weight decay .0005.',
        f'- Seed **{", ".join(map(str,seeds))}**, 조건별 **{rounds}라운드**. 공격 조건에서 C0 한 명만 악성.',
        '- 고정 정책: S=10,000, Q=65,536, 좌표 B=20,000, norm 제곱 T=2,500,000,000(L2 반경 5), 최소 통과 2명.',
        '- 무필터와 평문 bound는 trusted reference. 비공개 비교군은 **실제 공식 Flower + active Rep4**이며 평문 대체 경로가 아니다.',
        '- MPC는 최신 seeded-component·holder-checked direct import·lane64 경로, 고정 aggregator 4명/최대 악성 1명 계약이다.',
        '', '같은 seed에서 초기 모델·분할·학습·정책·공격 규칙을 맞췄다. 필터 유무로 모델이 달라진 뒤에는 각 현재 모델에서 새로 학습한다. 평문 필터와 MPC는 각 라운드 동일한 입력·정수 합·모델인지 별도로 검증했다.',
        '', '공격은 C0의 **자기 업데이트를 부호 반전·확대**하여 L2 반경 약 10으로 만들고, 모든 좌표는 B 안에 유지한다. 최종 양자화 정수가 canonical signed wire 범위 안에 있고 전체 norm만 T를 넘는지 확인한다. Honest 업데이트를 공격 생성에 제공하지 않는다. Client의 정직한 사전 검사를 명시적 test hook으로 우회하여 MPC가 직접 거부하는지 시험하며 제품의 검사·정책은 변경하지 않는다.',
        '', '## 최종 정확도','',
        '평균 ±는 3개 seed의 표본 표준편차이며 신뢰구간이 아니다.','',
        '| 조건 | 집계 방식 | seed별 최종 정확도 | 평균 ± 표준편차 |','|---|---|---|---|']
    for r in summary:
        std=r['sample_std_percentage_points'] or 0.
        text.append(f'| {"정상" if r["case"]=="clean" else "L2 범위 초과 공격"} | {labels[r["variant"]]} | '+
                    ' / '.join(f'{v:.2f}%' for v in r['final_accuracy_percent'])+f' | {r["mean_final_accuracy_percent"]:.2f}% ± {std:.2f}%p |')
    base=row('clean','mean')['mean_final_accuracy_percent'];bad=row('norm-overflow','mean')['mean_final_accuracy_percent'];filtered=row('norm-overflow','static-filter')['mean_final_accuracy_percent']
    text+=['',f'무필터 공격 조건은 정상 대비 **{base-bad:.2f}%p** 낮아졌다. Bound 검사 조건은 무필터 공격 대비 **{filtered-bad:.2f}%p** 높았고, 정상 기준 대비 차이는 **{base-filtered:.2f}%p**였다.',
        '',f'![라운드별 정확도 비교]({public.name}/accuracy.png)','',
        '평문 bound와 비공개 MPC의 곡선이 겹치는 것은 측정 오류가 아니라 매 라운드 모델이 정확히 같다는 결과다. 정상 조건과 공격 조건의 정상 기준 비교는 참여 인원 4→3의 차이도 포함하므로 정확도가 동일해야 한다고 가정하지 않는다.',
        '', '## 입력 제외와 정상 학습 유지','',
        '| 조건 | 방식 | 악성 입력 제외 | 정상 입력 제외 |','|---|---|---|---|']
    for r in summary:
        malicious='해당 없음' if r['case']=='clean' else f'{r["malicious_rejected"]}/{r["malicious_submissions"]}'
        text.append(f'| {"정상" if r["case"]=="clean" else "L2 초과"} | {labels[r["variant"]]} | {malicious} | {r["honest_rejected"]}/{r["honest_submissions"]} |')
    text+=['','무필터의 제외 수는 검사 없이 전원을 평균에 포함했다는 뜻이다. 제외율은 trusted 실험 oracle에서 구한 평가 지표이며 제품 서버에 개별 norm·통과 비트를 새로 공개한 것이 아니다.',
        '', '## 실제 MPC 정확성','',
        '| seed | 조건 | 확인한 라운드 | 정수 SUM/count | 모델·accuracy/loss |','|---|---|---:|---|---|']
    for c in comparisons:text.append(f'| {c["seed"]} | {c["case"]} | {len(c["rounds"])} | 전체 정확히 일치 | 전체 정확히 일치 |')
    text+=['','각 native 실행의 독립 재학습·수신증명·입력/결과 인증서·중복 모델 적용 방지도 검증했다. 모델 비교에 부동소수점 허용 오차를 적용하지 않았다.',
        '', '## MPC 비용: 등록과 라운드 분리','',
        '네 aggregator의 추적된 Player payload **송신 합계**이며 각 transmission은 한 번만 센다. Live preprocessing을 포함하지만 TLS/TCP/IP·native framing·미추적 exchange와 Flower/RPC 통신은 제외한다. 전체 시스템 통신량으로 표현하지 않는다.',
        '', '| seed | 조건 | 초기 setup bytes | round 1~5 송신량(MB, 10⁶ bytes) | ServerApp wall(초) |','|---|---|---:|---|---:|']
    for n in native_runs:text.append(f'| {n["seed"]} | {n["case"]} | {n["native_setup_sent_bytes"]:,} | '+
                ' / '.join(f'{v/1e6:.2f}' for v in n['native_round_sent_bytes'])+f' | {n["serverapp_wall_seconds"]:.2f} |')
    text+=['','Setup·round·shutdown counter 합을 global counter와 대조했다. 회로 compile/cache 조회와 seed 등록은 세션 준비 단계이며 라운드마다 재등록·재컴파일하지 않는다. Wall time은 학습·수집·MPC·인증을 포함한다. 평문 reference의 cache/직렬 학습과 Flower scheduling 조건이 달라 단순 시간 비율을 MPC 오버헤드로 주장하지 않는다.',
        '', '## 검증 범위와 한계','',
        '- 이번 결과는 **범위를 넘는 악성 입력을 제외하면서 개별 업데이트를 직접 열지 않는 검사·집계**의 기능과 학습 효과를 보여준다.',
        '- Norm 안의 poisoning, 실제 SGD 수행 여부, 모든 공격에 대한 방어를 증명하지 않는다.',
        '- 실제 MPC 학습은 **동일 WSL UID의 trusted local Flower Simulation harness**다. 최신 독립-host 구현을 네 기관에 배포한 시험이 아니다.',
        '- Post-run 정수·학습 대조를 위한 raw 업데이트 audit은 로컬 private `.cache`에만 만들었다. 일반 사용자 경로의 audit 정책이나 서버 권한을 확대하지 않았다.',
        '- Aggregator 2명 공모, 공개 SUM/count/모델에서의 역추론, 전체 FL composition 프라이버시·DP·BFT liveness 증명을 대신하지 않는다.',
        '- 3개 seed와 IID·클라이언트 4명·한 공격 조건의 결과이며 다른 모델·규모·non-IID로 일반화하지 않는다.',
        '', '## 재현과 공개 자료','',
        '```bash', '.venv/bin/python -u -m experiments.run_graduation_three_way \\',
        '  --output .cache/new-graduation-three-way \\',
        '  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1 \\',
        '  --report docs/reproduction/new-three-way.md --seeds 42 43 44 --rounds 5', '```',
        '',f'[공개 결과·정확성·비용 JSON]({public.name}/results.json), [소스·공개 파일 hash]({public.name}/manifest.json).',
        'Native와 평문 학습을 순차 실행한다. 개인 키·seed·학습 데이터·raw 업데이트·SQLite 상태는 공개 파일에 포함하지 않는다. Hub 게시·계정 설정은 하지 않았다.']
    report.write_text('\n'.join(text)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mp-spdz-dir',type=Path,required=True)
    parser.add_argument('--report',type=Path);parser.add_argument('--seeds',type=int,nargs='+',default=[42,43,44])
    parser.add_argument('--rounds',type=int,default=5);parser.add_argument('--native-worker',action='store_true')
    parser.add_argument('--case',choices=CASES)
    args=parser.parse_args();output=args.output.resolve();installation=args.mp_spdz_dir.resolve()
    os.environ.update(PATH=str(ROOT/'.venv/bin')+':/usr/local/bin:/usr/bin:/bin',
        OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',MKL_NUM_THREADS='1',RAY_USAGE_STATS_ENABLED='0')
    if args.native_worker:
        native(output,installation,args.seeds[0],args.case,args.rounds);return
    if args.report is None:parser.error('--report required')
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    from experiments.run_seed_mpc_poisoning import run,POLICY
    configuration={'seeds':args.seeds,'rounds':args.rounds,'cases':list(CASES),'policy':asdict(POLICY),
        'source_sha256':{n:sha(ROOT/n) for n in SOURCES},'native_backend':str(installation)}
    if (output/'configuration.json').exists():assert read(output/'configuration.json')==configuration
    else:write(output/'configuration.json',configuration)
    run(output/'oracle',args.seeds,list(CASES),rounds=args.rounds,malicious=1)
    for seed in args.seeds:
        for case in CASES:
            directory=output/f'native-seed-{seed}-{case}'
            if (directory/'verification.json').exists():
                assert read(directory/'verification.json')['passed'];continue
            if directory.exists():raise RuntimeError('incomplete native directory: fresh session required')
            command=[sys.executable,'-u','-m','experiments.run_graduation_three_way','--native-worker',
                '--output',str(directory),'--mp-spdz-dir',str(installation),'--seeds',str(seed),
                '--case',case,'--rounds',str(args.rounds)]
            print('START_NATIVE',seed,case,flush=True)
            with directory.with_suffix('.log').open('x') as log:subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True)
            print('VERIFIED_NATIVE',seed,case,flush=True)
    export(output,args.report.resolve(),args.seeds,args.rounds)
    print('THREE_WAY_COMPLETED',str(args.report.resolve()),flush=True)


if __name__=='__main__':main()

"""Matched fresh Flower plaintext/MPC cost study; no SGD cache across arms."""
import argparse
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib

import numpy as np
import tomli_w

from experiments.run_fmnist_flower import read_dataset
from experiments.run_seed_mpc_poisoning import vector_hash
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_training import initial_lenet, train_lenet, evaluate_lenet
from trustlessfl.seed_mpc_poisoning_fixture import attack
from trustlessfl.crypto import digest

ROOT = Path(__file__).resolve().parents[1]
POLICY = SeedMPCPolicy(61706, 4, 20000, 2500000000)
TRAINING = dict(epochs=1, batch_size=64, learning_rate=.01, momentum=.9, weight_decay=.0005)
VARIANTS = ('plain-mean', 'plain-bound', 'private-mpc')
SOURCES = ('experiments/run_flower_cost_comparison.py', 'trustlessfl/research_cost_flower.py',
           'experiments/run_seed_mpc_flower.py', 'experiments/run_endpoint_flower.py',
           'trustlessfl/seed_mpc_client_app.py', 'trustlessfl/seed_mpc_server_app.py',
           'trustlessfl/seed_mpc_dropout.py', 'trustlessfl/seed_mpc_committee.py', 'trustlessfl/seed_mpc_ledger.py',
           'trustlessfl/seed_mpc_training.py', 'trustlessfl/seed_mpc_poisoning_fixture.py',
           'trustlessfl/seed_mpc_meter.py', 'trustlessfl/seed_mpc_flower_runtime.py',
           'trustlessfl/seed_mpc_policy.py', 'trustlessfl/fmnist.py')


def read(path): return json.loads(Path(path).read_text())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path, value):
    path = Path(path); tmp = path.with_suffix(path.suffix+'.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n'); tmp.replace(path)


def stage_plain(output, seed, case, variant, rounds=5):
    from trustlessfl.seed_mpc_client_app import TrainingCalls
    data = read_dataset(ROOT/'.cache/fashion-mnist/FashionMNIST/raw')
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    clients = output/'clients'; clients.mkdir(mode=0o700)
    order = np.random.default_rng(seed).permutation(60000)
    records = {}
    for index, indices in enumerate(np.array_split(order, 4)):
        directory = clients/f'C{index}'; directory.mkdir(mode=0o700)
        (directory/'audit').mkdir(mode=0o700)
        path = directory/'train.npz'
        np.savez_compressed(path, x=data['train_x'][indices], y=data['train_y'][indices]); path.chmod(0o600)
        TrainingCalls(directory/'calls.sqlite', create=True).close()
        records[f'C{index}'] = {'sha256':sha(path), 'rows':15000,
                              'indices_sha256':hashlib.sha256(indices.astype('<i8').tobytes()).hexdigest()}
    test = output/'public-test.npz'; np.savez_compressed(test, x=data['test_x'], y=data['test_y'])
    cfg = {'trusted-plaintext-cost-benchmark':True,'variant':variant,'case':case,'seed':seed,
           'rounds':rounds,'policy':asdict(POLICY),'training':TRAINING,
           'client_root':str(clients),'test_data':str(test),'initial_model':initial_lenet(seed).tolist()}
    write(output/'deployment.json', cfg)
    app = output/'app'; app.mkdir()
    shutil.copytree(ROOT/'trustlessfl', app/'trustlessfl', ignore=shutil.ignore_patterns('__pycache__'))
    flower = tomllib.loads((ROOT/'configs/endpoint/flower-pyproject.toml').read_text())
    flower['project'].update(name='trustlessfl-cost-reference',description='Explicit local trusted cost reference')
    flower['project']['dependencies'] += ['cryptography>=46.0.7,<47',f'torch=={importlib.metadata.version("torch")}']
    flower['tool']['flwr']['app']['components'] = {'serverapp':'trustlessfl.research_cost_flower:server_app',
                                                'clientapp':'trustlessfl.research_cost_flower:client_app'}
    flower['tool']['flwr']['app']['config'] = {'deployment-file':str(output/'deployment.json'),
        'output-dir':str(output/'runtime-results'),'num-clients':4,'backend':'numpy','simulation-workers':1,
        'seed-mpc-runtime-guard':True,'seed-mpc-runtime-guard-sha256':sha(ROOT/'trustlessfl/seed_mpc_flower_runtime.py'),
        'runtime-cli-timeout':6600}
    (app/'pyproject.toml').write_text(tomli_w.dumps(flower))
    write(output/'provenance.json', {'data':records,'test_sha256':sha(test),
                                   'source_sha256':{s:sha(ROOT/s) for s in SOURCES}})


def result_of(directory):
    found = list((directory/'runtime-results').glob('run-*/results.json'))
    assert len(found) == 1
    return read(found[0])


def verify_plain(directory):
    cfg = read(directory/'deployment.json'); provenance = read(directory/'provenance.json')
    result = result_of(directory); model = np.asarray(cfg['initial_model'], dtype=np.float64)
    assert result['models'][0] == model.tolist()
    with np.load(cfg['test_data'], allow_pickle=False) as saved: tx,ty = saved['x'],saved['y']
    assert sha(cfg['test_data']) == provenance['test_sha256']
    assert evaluate_lenet(model,tx,ty) == result['metrics'][0]
    checks = []
    for r, (record, after, metric) in enumerate(zip(result['records'], result['models'][1:], result['metrics'][1:], strict=True),1):
        updates = []; keep = []
        for index in range(4):
            client = directory/f'clients/C{index}'
            assert sha(client/'train.npz') == provenance['data'][f'C{index}']['sha256']
            with np.load(client/'train.npz',allow_pickle=False) as saved:
                delta,meta = train_lenet(model,saved['x'],saved['y'],seed=cfg['seed'],slot=index,round_id=r,**TRAINING)
            q = np.rint(delta*POLICY.scale).astype(np.int64)
            if index == 0: q = attack(q,cfg['case'],POLICY)
            audit = read(client/f'audit/round-{r}.json')
            assert q.tolist() == audit['update'] and audit['model_hash'] == digest(model.tolist())
            assert audit['training'] == meta
            updates.append(q)
            keep.append(cfg['variant']=='plain-mean' or
                        (np.all(np.abs(q)<=POLICY.coordinate_cap) and sum(int(v)**2 for v in q)<=POLICY.squared_threshold))
        expected = {'status':'abort'} if sum(keep)<2 else {'status':'ok','count':int(sum(keep)),
            'sum':[sum(int(q[j]) for q,k in zip(updates,keep) if k) for j in range(POLICY.dimension)]}
        assert record['result'] == expected and record['selected'] == [bool(v) for v in keep]
        if expected['status']=='ok': model=model+np.asarray(expected['sum'],dtype=np.float64)/(POLICY.scale*expected['count'])
        assert model.tolist() == after and evaluate_lenet(model,tx,ty) == metric
        checks.append({'round':r,'independent_retraining_exact':True,'sum_exact':True,'model_exact':True})
    write(directory/'verification.json',{'passed':True,'checks':checks,'scope':'trusted plaintext reference; no private-protocol claim'})


def worker(directory, installation, seed, case, variant):
    stage_start = time.monotonic()
    if variant == 'private-mpc':
        from experiments.run_seed_mpc_flower import stage,run,verify_run
        stage(directory, installation, mode='fmnist-lenet5', seed=seed, rounds=5, timeout=1200,
              snapshot_version=2, collection_window_ms=600000, communication_meter=True,
              test_audit=True,test_poisoning=case,chunk_blocks=64,component_input='holder-checked-direct-v1',
              compile_cache=ROOT/'.cache/noniid-threshold-circuits')
    else:
        from experiments.run_endpoint_flower import run
        stage_plain(directory,seed,case,variant)
    stage_seconds = time.monotonic()-stage_start
    started = time.monotonic(); run(directory); harness_seconds = time.monotonic()-started
    verify_started = time.monotonic()
    if variant=='private-mpc': verify_run(directory)
    else: verify_plain(directory)
    write(directory/'cost-run.json',{'variant':variant,'case':case,'seed':seed,
        'stage_seconds':stage_seconds,'harness_seconds':harness_seconds,
        'post_run_verify_seconds':time.monotonic()-verify_started,
        'verified':True,'source_sha256':{s:sha(ROOT/s) for s in SOURCES}})


def communication(meter, native=None):
    setup={}; rounds={}
    for total in meter['totals']:
        destination = setup if total['scope']=='setup' else rounds.setdefault(total['scope'],{})
        key=total['channel']+'-'+total['direction']
        destination[key]=destination.get(key,0)+total['bytes']
    native_rounds = [r['sent_bytes'] for r in native['rounds']] if native else [0]*5
    rows=[]
    for r in range(1,6):
        group=rounds.get(f'round-{r}',{})
        flower_sent=group.get('flower-graph-sent',0); flower_received=group.get('flower-graph-received',0)
        rpc_sent=group.get('aggregator-rpc-json-sent',0);rpc_received=group.get('aggregator-rpc-json-received',0)
        rows.append({'round':r,'flower_server_to_clients_bytes':flower_sent,
            'flower_clients_to_server_bytes':flower_received,'aggregator_rpc_sent_bytes':rpc_sent,
            'aggregator_rpc_received_bytes':rpc_received,'native_player_sent_bytes':native_rounds[r-1],
            'tracked_layer_payload_bytes':flower_sent+flower_received+rpc_sent+rpc_received+native_rounds[r-1]})
    return {'application_setup':setup,'rounds':rows,
            'native_setup_sent_bytes':native['setup_sent_bytes'] if native else 0,
            'native_shutdown_sent_bytes':native['shutdown_sent_bytes'] if native else 0,
            'scope':'Flower graph + coordinator RPC JSON + native tracked Player sent; distinct boundaries; excludes wire headers/untracked IPC; not full physical network traffic'}


def export(output,report,jobs):
    rows=[]; exact=[]
    old=read(ROOT/'docs/reproduction/graduation-three-way-2026-10-12/results.json')
    for seed,case,variant in jobs:
        directory=output/f'{seed}-{case}-{variant}'
        assert read(directory/'verification.json')['passed']
        body=result_of(directory); timing=read(directory/'cost-run.json')
        verification=read(directory/'verification.json')
        if variant=='private-mpc':
            app=body['communication']['application'];native=body['communication']['native']
            counts=[record['result_certificate']['body']['result']['count'] for record in body['records']]
        else:
            app=body['communication'];native=None
            counts=[record['result']['count'] for record in body['records']]
        # Reconcile application totals from events rather than trusting export.
        from trustlessfl.seed_mpc_meter import ApplicationMeter
        recalc=ApplicationMeter()
        for event in app['events']:
            recalc.record(event['channel'],event['direction'],event['kind'],event['bytes'],
                          scope=event['scope'],objects=event.get('objects'))
        assert recalc.report()==app
        attempts=list(directory.glob('attempt-*/timing.json'));assert len(attempts)==1
        cli_wall=read(attempts[0])['flwr_cli_wall_seconds']
        client_timings=[read(directory/f'clients/C{i}/timing-round-{r}.json') for r in range(1,6) for i in range(4)]
        rows.append({'seed':seed,'case':case,'variant':variant,'serverapp_seconds':body['wall_seconds'],
            'flower_cli_seconds':cli_wall,**timing,'metrics':body['metrics'],'counts':counts,
            'round_timings':body['round_timings'],'communication':communication(app,native),
            'client_training_quantization_seconds':sum(r['training_and_quantization_seconds'] for r in client_timings),
            'client_training_quantization_by_round_seconds':[sum(r['training_and_quantization_seconds'] for r in client_timings if r['round']==n) for n in range(1,6)],
            'native_external_seed_setup':verification.get('communication',{}).get('external_seed_input'),
            'encrypted_seed_provisioning':verification.get('communication',{}).get('component_seed_provisioning'),
            'compilation':verification.get('compilation'),
            'verification_sha256':sha(directory/'verification.json')})
        old_report=next(p for p in old['plain_reports'] if p['seed']==seed and p['case']==case)
        for r in range(1,6):
            name='mean' if variant=='plain-mean' else 'static-filter'
            expected=old_report['rounds'][r-1]['variants'][name]
            assert vector_hash(np.asarray(body['models'][r],dtype=np.float64))==expected['model_sha256']
            assert body['metrics'][r]['accuracy']==expected['metrics']['accuracy']
        print('MATCHES_PREVIOUS_EFFECT',seed,case,variant,flush=True)
    for seed,case in dict.fromkeys((s,c) for s,c,_ in jobs):
        directories={v:output/f'{seed}-{case}-{v}' for v in VARIANTS}
        plain=result_of(directories['plain-bound']);private=result_of(directories['private-mpc'])
        for i in range(4):
            pins=[read(directories[v]/'provenance.json')['data'][f'C{i}']['indices_sha256'] for v in VARIANTS]
            assert len(set(pins))==1
        assert plain['models']==private['models'] and plain['metrics']==private['metrics']
        for r in range(1,6):
            assert plain['records'][r-1]['result']==private['records'][r-1]['result_certificate']['body']['result']
            for i in range(4):
                left=read(directories['plain-bound']/f'clients/C{i}/audit/round-{r}.json')
                right=read(directories['private-mpc']/f'clients/C{i}/audit/round-{r}.json')
                assert left['update']==right['update'] and left['training']==right['training']
        exact.append({'seed':seed,'case':case,'input_comparisons':20,'input_model_sum_count_metrics_exact':True})
    summary=[]
    for case in ('clean','norm-overflow'):
        for variant in VARIANTS:
            group=[r for r in rows if r['case']==case and r['variant']==variant]
            values=[r['serverapp_seconds'] for r in group]
            summary.append({'case':case,'variant':variant,'n':len(group),'mean_serverapp_seconds':float(np.mean(values)),
                'std_serverapp_seconds':float(np.std(values,ddof=1)) if len(values)>1 else None,
                'mean_flower_cli_seconds':float(np.mean([r['flower_cli_seconds'] for r in group])),
                'mean_harness_seconds':float(np.mean([r['harness_seconds'] for r in group])),
                'mean_tracked_round_payload_bytes':float(np.mean([sum(t['tracked_layer_payload_bytes'] for t in r['communication']['rounds']) for r in group])),
                'mean_client_training_seconds':float(np.mean([r['client_training_quantization_seconds'] for r in group])),
                'mean_final_accuracy_percent':float(np.mean([100*r['metrics'][-1]['accuracy'] for r in group]))})
    ratios=[]
    for seed,case in dict.fromkeys((s,c) for s,c,_ in jobs):
        group={r['variant']:r for r in rows if r['seed']==seed and r['case']==case};mpc=group['private-mpc']
        for variant in ('plain-mean','plain-bound'):
            base=group[variant]
            native_bytes=sum(t['tracked_layer_payload_bytes'] for t in mpc['communication']['rounds'])
            base_bytes=sum(t['tracked_layer_payload_bytes'] for t in base['communication']['rounds'])
            ratios.append({'seed':seed,'case':case,'baseline':variant,
                'serverapp_ratio':mpc['serverapp_seconds']/base['serverapp_seconds'],
                'serverapp_extra_seconds':mpc['serverapp_seconds']-base['serverapp_seconds'],
                'flower_cli_ratio':mpc['flower_cli_seconds']/base['flower_cli_seconds'],
                'tracked_payload_ratio':native_bytes/base_bytes,'tracked_payload_extra_bytes':native_bytes-base_bytes})
    public=report.with_suffix('');public.mkdir(parents=True,exist_ok=True)
    body={'completed':True,'configuration':read(output/'configuration.json'),'runs':rows,'summary':summary,
          'paired_ratios':ratios,'exact_comparisons':exact,
          'scope':'fresh official Flower Simulation in one WSL UID; full design overhead vs plaintext references, not pure MPC primitive speed; payload counters, not physical network traffic'}
    write(public/'results.json',body)
    plot(public,summary)
    markdown(report,body)
    write(public/'manifest.json',{'files':{f.name:sha(f) for f in public.iterdir() if f.is_file() and f.name!='manifest.json'},
        'report_sha256':sha(report),'source_sha256':read(output/'configuration.json')['source_sha256']})
    print('FLOWER_COST_COMPLETED',report,flush=True)


def plot(public,summary):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    labels={'plain-mean':'Plain mean','plain-bound':'Plain bound','private-mpc':'Private MPC'}
    rows=[r for r in summary if r['case']=='norm-overflow']
    fig,axes=plt.subplots(1,2,figsize=(10,4))
    axes[0].bar([labels[r['variant']] for r in rows],[r['mean_serverapp_seconds'] for r in rows],color=['#64748b','#2563eb','#059669'])
    axes[0].set_ylabel('ServerApp seconds / 5 rounds');axes[0].set_title('Fresh Flower / CPU / 3 seeds')
    axes[1].bar([labels[r['variant']] for r in rows],[r['mean_tracked_round_payload_bytes']/1e6 for r in rows],color=['#64748b','#2563eb','#059669'])
    axes[1].set_ylabel('Tracked layer payload MB / 5 rounds');axes[1].set_title('Body counters; excludes wire overhead')
    fig.tight_layout();fig.savefig(public/'cost.png',dpi=180);plt.close(fig)


def markdown(report,body):
    public=report.with_suffix('');labels={'plain-mean':'무필터 평문','plain-bound':'평문 bound','private-mpc':'비공개 MPC'}
    text=['# 같은 Flower 환경의 평문·MPC 비용 비교','',
          '2026-10-12. 새로 실행한 비용 비교다. 앞선 순차 reference 시간이나 SGD cache 시간을 분모로 사용하지 않는다.','',
          '## 비교 조건','',
          '- Full FMNIST train 60,000 / test 10,000, LeNet5 61,706개 파라미터, IID client 4명·각 15,000개.',
          '- CPU local epoch 1, batch 64, lr .01 / momentum .9 / weight decay .0005, S=10,000, B=20,000, L2 반경 5, 최소 통과 2.',
          '- 공식 Flower Simulation/Ray, simulation worker 1, 동일 dependency/runtime guard, 각 실행 별도 SuperLink/세션/클라이언트 상태. 동시에 실행하지 않았다.',
          '- 정상 seed 42는 교차 확인 1회/방식, 공격 seed 42·43·44는 3회/방식. 총 **12개 실행·60라운드**, 그중 **실제 MPC 4회·20라운드**.',
          '- 세 방식 모두 각 라운드 현재 모델에서 새로 SGD를 수행한다. 다른 방식·라운드의 학습 결과를 cache로 대체하지 않는다. 프로토콜 재전송용 durable cache는 별도다.',
          '- 공격 C0는 자기 업데이트를 부호 반전/확대하여 L2 약 10으로 만들고 좌표 상한은 지킨다. 이전 효과 실험과 모델/정확도가 정확히 일치하는지 검증했다.',
          '- 평문은 별도 trusted 연구용 앱으로 signed16 업데이트를 서버에 공개한다. 일반 사용자·private MPC 경로를 평문으로 바꾸지 않았다.',
          '- 평문도 모델 commit/ack와 로컬 audit을 수행한다. MPC에는 4-party privacy·악성 검사·마스킹·인증서·수신증명·동기화 비용이 추가된다. 측정 배율은 **전체 구현의 추가 비용**이며 MPC 곱셈 연산만의 배율이 아니다.',
          '- 최초 공통 학습 setup과 회로 준비, 실제 Flower 실행, 사후 독립 재학습 검증 시간을 분리했다. 각 모드의 전체 private 자료는 local .cache에만 있다.', '',
          '## 시간과 학습 효과','',
          '| 조건 | 방식 | 반복 | ServerApp 평균 초 ± SD | Flower CLI 평균 초 | 최종 정확도 평균 |',
          '|---|---|---:|---|---:|---:|']
    for row in body['summary']:
        sd='' if row['std_serverapp_seconds'] is None else f' ± {row["std_serverapp_seconds"]:.2f}'
        text.append(f'| {row["case"]} | {labels[row["variant"]]} | {row["n"]} | {row["mean_serverapp_seconds"]:.2f}{sd} | {row["mean_flower_cli_seconds"]:.2f} | {row["mean_final_accuracy_percent"]:.2f}% |')
    text += ['', 'ServerApp wall은 등록/평가·학습/수집·검사/집계·모델 적용/통지를 포함한다. Flower CLI wall은 런타임 배포/기동 등도 포함한다. 사후 oracle 검증 시간은 둘에 포함하지 않는다. SD는 3 seeds의 표본 표준편차이며 CI가 아니다. 정상 1회에는 SD를 제시하지 않는다.', '',
             '## 같은 seed에서의 추가 비용','',
             '| 조건 | seed | 분모 | ServerApp 배율 | 추가 초/5r | Flower CLI 배율 | 추적 payload 배율 | 추가 payload MB/5r |',
             '|---|---:|---|---:|---:|---:|---:|---:|']
    for row in body['paired_ratios']:
        text.append(f'| {row["case"]} | {row["seed"]} | {labels[row["baseline"]]} | {row["serverapp_ratio"]:.2f}× | {row["serverapp_extra_seconds"]:.2f} | {row["flower_cli_ratio"]:.2f}× | {row["tracked_payload_ratio"]:.2f}× | {row["tracked_payload_extra_bytes"]/1e6:.2f} |')
    text += ['', f'![비용 비교]({public.name}/cost.png)', '',
             '## 통신 계층','',
             '세 계층의 관측 payload를 분리했다. Flower graph는 coordinator 경계의 실제 deflate 크기(배열/record/message 포함), RPC는 coordinator 경계의 JSON body, native는 4-party Player의 추적 송신 합계다. 서로 다른 링크의 전송을 한 번씩 센다. **전체 TCP/TLS wire나 미추적 IPC 트래픽을 측정한 것은 아니다.**', '',
             '| 조건/seed | 방식 | 5r Flower server→clients MB | clients→server MB | aggregator RPC 양방향 MB | native Player 송신 MB | 관측 계층 합 MB |',
             '|---|---|---:|---:|---:|---:|---:|']
    for run in body['runs']:
        comm=run['communication']['rounds']
        values=[sum(r[k] for r in comm)/1e6 for k in ('flower_server_to_clients_bytes','flower_clients_to_server_bytes')]
        rpc=sum(r['aggregator_rpc_sent_bytes']+r['aggregator_rpc_received_bytes'] for r in comm)/1e6
        player=sum(r['native_player_sent_bytes'] for r in comm)/1e6
        total=sum(r['tracked_layer_payload_bytes'] for r in comm)/1e6
        text.append(f'| {run["case"]}/{run["seed"]} | {labels[run["variant"]]} | {values[0]:.3f} | {values[1]:.3f} | {rpc:.3f} | {player:.3f} | {total:.3f} |')
    text += ['', '## 초기 준비와 라운드별 비용','',
             '| 조건/seed | 방식 | stage 초 | harness 초 | 초기 native setup bytes | compile/cache |', '|---|---|---:|---:|---:|---|']
    for run in body['runs']:
        compilation=run['compilation']
        compile_text='없음' if compilation is None else 'cache hit' if compilation['hit'] else f'{compilation["compile_seconds"]:.3f}초'
        text.append(f'| {run["case"]}/{run["seed"]} | {labels[run["variant"]]} | {run["stage_seconds"]:.3f} | {run["harness_seconds"]:.3f} | {run["communication"]["native_setup_sent_bytes"]} | {compile_text} |')
    text += ['', 'stage는 데이터/앱 복사 및 초기 모델, MPC에서는 역할 키/TLS/provisioning·회로 준비도 포함한다. 회로 cache의 cold compile 비용은 이번 warm-cache 실행의 stage에 포함하지 않는다. Setup Flower/RPC, 외부 등록 연결과 암호화 seed packet 크기도 JSON에 별도로 기록했다. Packet 파일 크기는 실제 네트워크 측정으로 표현하지 않는다.', '',
             '| 조건/seed | 방식 | round 1~5 단계 합계 초 | round 1~5 관측 payload MB | client SGD/양자화/공격 합계 초(5r) |', '|---|---|---|---|---:|']
    for run in body['runs']:
        durations=[sum(v for k,v in r.items() if k.endswith('_seconds')) for r in run['round_timings']]
        amounts=[r['tracked_layer_payload_bytes']/1e6 for r in run['communication']['rounds']]
        text.append(f'| {run["case"]}/{run["seed"]} | {labels[run["variant"]]} | '+' / '.join(f'{v:.2f}' for v in durations)+' | '+' / '.join(f'{v:.2f}' for v in amounts)+f' | {run["client_training_quantization_seconds"]:.3f} |')
    text += ['', '평문 check_and_sum과 MPC execute/result_certificate의 원시 구간 시간은 JSON에 있다. MPC 구간에는 결과 인증이 포함돼 순수 회로 실행 시간과 같지 않다. Client work도 모델 동기화/마스킹/서명 전체 시간을 의미하지 않는다.', '',
             '## 정확성과 범위','',
             f'- 평문 bound/MPC의 **{sum(r["input_comparisons"] for r in body["exact_comparisons"])}개 client-round** 입력과 모델·정수 합·count·metrics가 정확히 일치했다.',
             '- 평문 두 방식도 독립 재학습·정수 산술로 검증했다. 이전 공격 효과 실험과 각 라운드 모델 hash/정확도가 모두 같았다.',
             '- 순차·고정 데이터/정책·CPU·WSL 단일 UID의 결과다. 4개 독립 물리 호스트에서의 latency/대역폭/보안 검증이 아니다.',
             '- 전송 형태도 비용의 일부다. 평문 signed16 binary ArrayRecord와 MPC의 서명된 masked JSON·인증서 전송을 비교했다.',
             '- 고정 5라운드이며 현재 인증서 chain 처리 비용이 포함된다. 더 긴 라운드의 비용을 단순 비례로 추정하지 않는다.',
             '- 공격 조건의 무필터 모델은 이후 다른 업데이트를 만든다. 순수 프라이버시 비용에 더 가까운 비교는 동일 입력/모델인 평문 bound↔MPC다.', '',
             '## 재현','', '```bash', '.venv/bin/python -u -m experiments.run_flower_cost_comparison \\',
             '  --output .cache/new-flower-cost \\',
             '  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1 \\',
             '  --report docs/reproduction/new-flower-cost.md', '```', '',
             f'[전체 결과·구간 시간 JSON]({public.name}/results.json), [소스/공개 파일 hash]({public.name}/manifest.json).']
    report.write_text('\n'.join(text)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--mp-spdz-dir',type=Path,required=True)
    parser.add_argument('--report',type=Path);parser.add_argument('--worker',action='store_true')
    parser.add_argument('--seed',type=int);parser.add_argument('--case',choices=('clean','norm-overflow'))
    parser.add_argument('--variant',choices=VARIANTS)
    args=parser.parse_args()
    os.environ.update(PATH=str(ROOT/'.venv/bin')+':/usr/local/bin:/usr/bin:/bin',OPENBLAS_NUM_THREADS='1',
                      OMP_NUM_THREADS='1',MKL_NUM_THREADS='1',RAY_USAGE_STATS_ENABLED='0')
    output=args.output.resolve();installation=args.mp_spdz_dir.resolve()
    if args.worker: worker(output,installation,args.seed,args.case,args.variant);return
    if args.report is None:parser.error('--report required')
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    jobs=[(42,'clean',v) for v in VARIANTS]
    for i,seed in enumerate((42,43,44)):
        order=VARIANTS[i:]+VARIANTS[:i]
        jobs += [(seed,'norm-overflow',v) for v in order]
    data=read_dataset(ROOT/'.cache/fashion-mnist/FashionMNIST/raw')
    cpu_model=next((s.split(':',1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')),platform.processor())
    config={'jobs':jobs,'policy':asdict(POLICY),'training':TRAINING,
            'host':{'platform':platform.platform(),'cpu':cpu_model,'logical_cpus':os.cpu_count()},
            'versions':{p:importlib.metadata.version(p) for p in ('flwr','ray','torch','numpy')},
            'data_sha256':{k:hashlib.sha256(v.tobytes()).hexdigest() for k,v in data.items()},
            'source_sha256':{s:sha(ROOT/s) for s in SOURCES},
            'scope':'fresh Flower matched-runtime benchmarks; research plaintext app separate from production'}
    if (output/'configuration.json').exists():assert read(output/'configuration.json')==json.loads(json.dumps(config))
    else:write(output/'configuration.json',config)
    for seed,case,variant in jobs:
        directory=output/f'{seed}-{case}-{variant}'
        if (directory/'cost-run.json').exists():assert read(directory/'cost-run.json')['verified'];continue
        if directory.exists():raise RuntimeError('unfinished session: preserve artifacts and use fresh output')
        command=[sys.executable,'-u','-m','experiments.run_flower_cost_comparison','--worker',
                 '--output',str(directory),'--mp-spdz-dir',str(installation),'--seed',str(seed),
                 '--case',case,'--variant',variant]
        print('START',seed,case,variant,flush=True)
        with (output/f'{seed}-{case}-{variant}.log').open('x') as log:
            subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True)
        print('VERIFIED',seed,case,variant,flush=True)
    assert config['source_sha256']=={s:sha(ROOT/s) for s in SOURCES}
    export(output,args.report.resolve(),jobs)


if __name__=='__main__':main()

"""Real full-FMNIST user models with a fixed client roster, four Rep4 parties."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import numpy as np

from experiments.run_fmnist_flower import read_dataset
from experiments.validate_seed_mpc_client_counts import reference_training
from trustlessfl.seed_mpc_user import prepare,run
from trustlessfl.seed_mpc_model import load_model_config,train_custom
from trustlessfl.seed_mpc_training import initial_lenet,train_lenet

ROOT=Path(__file__).resolve().parents[1]
SOURCES=('trustlessfl/seed_mpc_dropout.py','trustlessfl/seed_mpc_server_app.py',
    'trustlessfl/seed_mpc_client_app.py','trustlessfl/seed_mpc_committee.py','trustlessfl/seed_mpc_user.py',
    'trustlessfl/seed_mpc_model.py','trustlessfl/seed_mpc_compile.py','trustlessfl/seed_mpc_flower_runtime.py',
    'trustlessfl/fmnist.py','examples/seed_mpc_fmnist_lenet5/classifier.py')
SOURCES+=('trustlessfl/mpc_sources/seed_mpc_chunked_session.py',)
SOURCES+=('trustlessfl/seed_mpc_service.py',)
SOURCES+=('trustlessfl/seed_mpc_session.py',)
SOURCES+=('examples/seed_mpc_custom/fmnist_small_cnn.py',)


def read(path):return json.loads(Path(path).read_text())
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,body):
    path=Path(path); temp=path.with_suffix(path.suffix+'.tmp')
    temp.write_text(json.dumps(body,ensure_ascii=False,indent=2)+'\n');temp.replace(path)


def data(output,clients,seed,model='lenet5'):
    raw=read_dataset(ROOT/'.cache/fashion-mnist/FashionMNIST/raw')
    assert len(raw['train_y'])==60000 and len(raw['test_y'])==10000 and 60000%clients==0
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    plugin = ('examples/seed_mpc_custom/fmnist_small_cnn.py' if model=='small-cnn'
              else 'examples/seed_mpc_fmnist_lenet5/classifier.py')
    shutil.copyfile(ROOT/plugin,output/'classifier.py')
    order=np.random.default_rng(seed).permutation(60000)
    indices=np.array_split(order,clients)
    np.save(output/'indices.npy',np.stack(indices).astype('<i8'),allow_pickle=False)
    assert np.array_equal(np.sort(np.concatenate(indices)),np.arange(60000))
    for i,part in enumerate(indices):
        np.savez_compressed(output/f'C{i}.npz',x=raw['train_x'][part],y=raw['train_y'][part])
    np.savez_compressed(output/'test.npz',x=raw['test_x'],y=raw['test_y'])
    cfg={'plugin':'classifier.py','kwargs':({'channels':[4,8],'classes':10} if model=='small-cnn' else {}),'train_data':[f'C{i}.npz' for i in range(clients)],
        'test_data':'test.npz','training':{'epochs':1,'batch_size':64,'learning_rate':.01,
            'momentum':.9,'weight_decay':.0005},
        'policy':{'coordinate_cap':20000,'squared_threshold':2500000000,'scale':10000,'minimum_accepted':2}}
    write(output/'model.json',cfg)
    spec,initial,training,_,_,_=load_model_config(output/'model.json',seed,expected_clients=clients)
    assert spec['schema']['dimension']==(666 if model=='small-cnn' else 61706)
    if model=='lenet5':
        assert np.array_equal(initial,initial_lenet(seed))
        with np.load(output/'C0.npz',allow_pickle=False) as saved:
            actual,meta=train_custom(spec,initial,saved['x'],saved['y'],slot=0,round_id=1,training=training)
            expected,oldmeta=train_lenet(initial,saved['x'],saved['y'],seed=seed,slot=0,round_id=1,**training)
        assert np.array_equal(actual,expected) and meta==oldmeta
    return {'train_rows':60000,'test_rows':10000,'rows_per_client':60000//clients,
        'indices_sha256':sha(output/'indices.npy'),'npz_sha256':{p.name:sha(p) for p in output.glob('*.npz')},
        'dimension':spec['schema']['dimension'],'model':model,
        'initial_and_first_client_match_existing_lenet':model=='lenet5'}


def export(output,report):
    config=read(output/'configuration.json');session=output/'session'
    verified=read(output/'independent-verification.json');summary=read(session/'summary.json')
    assert summary['completed'] and verified['raw_audit_files']==0
    result=read(next((session/'runtime-results').glob('run-*/results.json')))
    for name,pin in config['source_sha256'].items():assert sha(ROOT/name)==pin
    native=result['communication']['native'];app=result['communication']['application'];rows=[]
    for r,timing in enumerate(result['round_timings'],1):
        totals={}
        for x in app['totals']:
            if x['scope']==f'round-{r}':totals[x['channel']+'-'+x['direction']]=x['bytes']
        player=native['rounds'][r-1]['sent_bytes']
        rows.append({'round':r,'accepted':verified['rounds'][r-1]['count'],
            'accuracy':result['metrics'][r]['accuracy'],'phase_seconds':timing,
            'flower_server_to_clients_bytes':totals.get('flower-graph-sent',0),
            'flower_clients_to_server_bytes':totals.get('flower-graph-received',0),
            'aggregator_rpc_bytes':totals.get('aggregator-rpc-json-sent',0)+totals.get('aggregator-rpc-json-received',0),
            'native_player_sent_bytes':player,'tracked_payload_bytes':sum(totals.values())+player})
    body={'completed':True,'clients':config['clients'],'aggregators':4,'dimension':config['data']['dimension'],
        'model':config['data']['model'],'prepare_seconds':read(output/'prepare-timing.json')['seconds'],
        'rows_per_client':config['data']['rows_per_client'],'training':config['training'],
        'rounds':rows,'metrics':result['metrics'],'serverapp_seconds':result['wall_seconds'],
        'compilation':verified['compilation'],'setup_native_bytes':native['setup_sent_bytes'],
        'resource':result['native_resources'],'widths':verified['widths'],
        'independent_sum_model_evaluation_exact':True,'raw_audit_files':0,
        'simulation_workers':config['simulation_workers'],'collection_window_ms':config['collection_window_ms'],
        'client_confirmed_rounds':result['client_confirmed_rounds'],
        'scope':'full public FMNIST; local WSL single UID; not independent operators/100 physical clients; tracked payload excludes wire headers and cross-message cache discounts'}
    report=report.resolve();public=report.with_suffix('');public.mkdir(parents=True,exist_ok=True)
    write(public/'results.json',body)
    text=[f'# FMNIST·{config["data"]["model"]} {config["clients"]}-client 실행 결과','',
        f'Aggregator 4명·클라이언트 {config["clients"]}명, {config["data"]["model"]} {config["data"]["dimension"]:,} parameters를 실제 Flower·Rep4로 {len(rows)}라운드 학습했다. FMNIST 전체 60,000개를 seed42 IID로 중복 없이 균등 분할했고 client당 {config["data"]["rows_per_client"]}개, test는 10,000개다. 일반 사용자 모델 실행 경로를 사용하고 raw 업데이트 audit은 생성하지 않았다.','',
        f'CPU Ray worker {config["simulation_workers"]}개이며 100개 물리 머신 실험은 아니다. 로컬 SGD 1 epoch, batch64, lr0.01, momentum0.9, weight decay0.0005, scale10000·정수 좌표 bound20000·real L2≤5·minimum accepted2를 사용했다. 각 client의 로컬 optimizer는 매 round 새로 만든다.','',
        '## 결과','', '| Round | 제출·통과 | 정확도 | 단계 합계 초 | Flower S→C MB | Flower C→S MB | aggregator RPC MB | native 4-party 송신 MB |',
        '|---:|---:|---:|---:|---:|---:|---:|---:|']
    for row in rows:
        duration=sum(v for k,v in row['phase_seconds'].items() if k.endswith('_seconds'))
        text.append(f'| {row["round"]} | {row["accepted"]}/{config["clients"]} | {100*row["accuracy"]:.2f}% | {duration:.2f} | '+
            ' | '.join(f'{row[k]/1e6:.2f}' for k in ('flower_server_to_clients_bytes','flower_clients_to_server_bytes','aggregator_rpc_bytes','native_player_sent_bytes'))+' |')
    text+=['',f'초기 정확도 {100*result["metrics"][0]["accuracy"]:.2f}%. ServerApp 전체 {result["wall_seconds"]:.2f}초. 초기 native setup {native["setup_sent_bytes"]:,} bytes. 컴파일 정보는 JSON에 별도로 기록했다.', '',
        '- 모든 client의 원래 NPZ로 독립 재학습하고 정확한 정수 SUM·모델 전이·평가를 대조했다. 단순히 프로세스 종료만 확인한 것이 아니다.',
        '- 동일 cursor의 전송 객체를 메모리에서 공유해 중복 할당을 줄였다. 전송 내용·검증·quorum·MPC는 생략하지 않는다.',
        '- Client당 600개라 로컬 optimizer step은 10개다. 기존 4명×15,000개 실험의 235 step과 달라 동일 round의 정확도/시간을 N만의 효과로 비교하지 않는다.',
        '- Generic adapter는 delta=학습 후 파라미터−공개 모델이다. 모든 round는 이 정의로 독립 검증했다.',
        '- Compact runtime client loop를 사용해 클라이언트마다 회로 코드를 복제하는 컴파일 비용을 줄였다. 준비된 입력을 각 aggregator의 자체 ledger에서 hash로 참조하고 prepare를 순차 호출해 RPC 메모리 복제를 줄였다. MPC 실행은 네 party가 함께 수행하며 입력 인증·바운더리 검사를 유지한다.',
        '- 2라운드의 목적은 100명 실제 실행·정확한 집계를 확인하는 것이다. 모델 수렴·포이즈닝 방어 성능이나 독립 호스트 배포를 검증한 실험은 아니다.',
        '- LeNet5 100명 시도는 컴파일·RPC 크기 제한을 개선한 뒤에도 현재 호스트의 메모리 압박과 WSL 실행 중단으로 완료하지 못했다. 이 결과는 666-parameter 모델의 결과이며 LeNet5 성공으로 해석하지 않는다.',
        '- 통신량은 Flower 논리 object graph/RPC body/native Player 카운터다. TCP/TLS 전체 wire와 미추적 IPC를 포함하지 않으며 Flower의 메시지 간 중복 제거/캐시는 할인하지 않은 지표다.',
        '- 정적 악성/공모 aggregator 최대 1명 가정과 출력 역추론 한계는 유지된다. 이 동작 실험이 전체 프라이버시 증명을 대신하지 않는다.','',
        f'[전체 결과·단계별 시간]({public.name}/results.json).']
    report.write_text('\n'.join(text)+'\n')
    write(public/'manifest.json',{'source_sha256':config['source_sha256'],
        'report_sha256':sha(report),'results_sha256':sha(public/'results.json')})
    print('LARGE_FMNIST_COMPLETED',report,flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--mp-spdz-dir',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True);p.add_argument('--clients',type=int,default=100)
    p.add_argument('--rounds',type=int,default=2);p.add_argument('--phase',choices=('all','prepare','run','verify'),default='all')
    p.add_argument('--model',choices=('lenet5','small-cnn'),default='lenet5')
    p.add_argument('--simulation-workers',type=int,default=2)
    args=p.parse_args();output=args.output.resolve()
    os.environ.update(PATH=str(ROOT/'.venv/bin')+':/usr/local/bin:/usr/bin:/bin',
        OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',MKL_NUM_THREADS='1',RAY_USAGE_STATS_ENABLED='0')
    if args.phase in ('all','prepare'):
        output.mkdir(parents=True,exist_ok=False,mode=0o700);tick=time.monotonic()
        print('PREPARING_DATA',args.clients,flush=True)
        provenance=data(output/'data',args.clients,42,args.model)
        collection_window_ms=600000 if args.model=='small-cnn' else 3600000
        cfg={'clients':args.clients,'rounds':args.rounds,'seed':42,'simulation_workers':args.simulation_workers,
            'collection_window_ms':collection_window_ms,'timeout':3600,'compile_timeout':3600,'data':provenance,
            'training':read(output/'data/model.json')['training'],'source_sha256':{s:sha(ROOT/s) for s in SOURCES}}
        write(output/'configuration.json',cfg);write(output/'progress.json',{'phase':'compiling-and-provisioning'})
        print('PREPARING_MPC_AND_ROLES',flush=True)
        prepare(output/'session',args.mp_spdz_dir,output/'data/model.json',clients=args.clients,
            rounds=args.rounds,seed=42,timeout=3600,collection_window_ms=collection_window_ms,
            compile_cache=ROOT/'.cache/seed-mpc-circuits',component_input='holder-checked-direct-v1',
            communication_meter=True,compile_timeout=3600,simulation_workers=args.simulation_workers,client_loop='compact-runtime-v1',
            rpc_material='prepared-reference-v1')
        write(output/'prepare-timing.json',{'seconds':time.monotonic()-tick})
        write(output/'progress.json',{'phase':'prepared'})
    if args.phase in ('all','run'):
        print('RUNNING_FLOWER',flush=True);write(output/'progress.json',{'phase':'running'})
        run(output/'session');write(output/'progress.json',{'phase':'public-verification-passed'})
    if args.phase in ('all','run','verify'):
        print('INDEPENDENT_RETRAINING',flush=True)
        verified=reference_training(output/'session');write(output/'independent-verification.json',verified)
        export(output,args.report);write(output/'progress.json',{'phase':'complete'})


if __name__=='__main__':main()

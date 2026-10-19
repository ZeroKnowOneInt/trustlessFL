"""Archive public poisoning results and compare native models to the oracle."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil

import numpy as np

ROOT=Path(__file__).resolve().parents[1]


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def export(oracle, native, output):
    from experiments.run_seed_mpc_poisoning import vector_hash
    from trustlessfl.seed_mpc_flower_runtime import learning_workload_completed
    # Reject incomplete learning runs before modifying any archived artifact,
    # including legacy verification files that called correct aborts "passed".
    for run in native:
        paths=list((run/'runtime-results').glob('run-*/results.json'))
        if len(paths)!=1: raise ValueError('one completed native result required')
        body=json.loads(paths[0].read_text())
        checks=[{'presence':record['manifest']['presence'],
                 'status':record['result_certificate']['body']['result']['status']}
                for record in body['records']]
        if not learning_workload_completed(checks,4):
            raise ValueError(f'incomplete all-present learning workload: {run.name}')
    output.mkdir(parents=True,exist_ok=True)
    def copy(source,relative):
        target=output/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
    for name in ('experiments/export_seed_mpc_poisoning.py','experiments/run_seed_mpc_poisoning_native_batch.py',
                 'experiments/verify_seed_mpc_isolated_fixture.py','experiments/run_seed_mpc_clean_recovery.py',
                 'tests/test_seed_mpc_flower_runtime.py','tests/test_endpoint_flower.py'):
        copy(ROOT/name,Path('sources')/name)
    config=json.loads((oracle/'configuration.json').read_text())
    expected={(seed,case) for seed in config['seeds'] for case in config['cases']}
    reports={}
    for source in sorted(oracle.glob('seed-*.json')):
        report=json.loads(source.read_text())
        if report['status']!='completed': continue
        assert len(report['rounds'])==config['rounds']
        reports[(report['seed'],report['case'])]=report
        copy(source,Path('oracle')/source.name)
    assert set(reports)==expected,'Incomplete matrix'
    copy(oracle/'configuration.json',Path('oracle/configuration.json'))
    copy(oracle/'summary.json',Path('oracle/summary.json'))
    for relative,expected_hash in config['source_sha256'].items():
        source=oracle/'sources'/relative
        assert sha(source)==expected_hash
        copy(source,Path('oracle/sources')/relative)
    groups=[]
    for case in config['cases']:
        for variant in ('mean','static-filter'):
            values=[];deltas=[]
            for seed in config['seeds']:
                metrics=reports[(seed,case)]['rounds'][-1]['variants'][variant]['metrics']
                clean=reports[(seed,'clean')]['rounds'][-1]['variants'][variant]['metrics']
                values.append(100*metrics['accuracy']);deltas.append(100*(clean['accuracy']-metrics['accuracy']))
            groups.append({'case':case,'variant':variant,'accuracy_percent':values,
                'mean_accuracy_percent':float(np.mean(values)),
                'sample_std_accuracy_percentage_points':float(np.std(values,ddof=1)) if len(values)>1 else None,
                'paired_clean_degradation_percentage_points':deltas,'mean_degradation_percentage_points':float(np.mean(deltas))})
    native_checks=[]
    for run in native:
        from trustlessfl.seed_mpc_wire import mask_words
        deployment=json.loads((run/'deployment.json').read_text())
        cfg=deployment['training'];case=cfg['test_poisoning']['case'];seed=cfg['seed']
        verification=json.loads((run/'verification.json').read_text())
        assert verification['passed']
        paths=list((run/'runtime-results').glob('run-*/results.json'));assert len(paths)==1
        body=json.loads(paths[0].read_text())
        oracle_report=reports[(seed,case)]
        checks=[]
        for row,record,model,metric in zip(oracle_report['rounds'],body['records'],body['models'][1:],body['metrics'][1:],strict=True):
            expected_row=row['variants']['static-filter'];actual=record['result_certificate']['body']['result']
            assert vector_hash(np.asarray(model,dtype=np.float64))==expected_row['model_sha256']
            assert actual['status']==expected_row['status']
            if actual['status']=='ok':
                assert actual['count']==expected_row['accepted_count']
                assert hashlib.sha256(np.asarray(actual['sum'],dtype='<i8').tobytes()).hexdigest()==expected_row['sum_sha256']
            assert metric['accuracy']==expected_row['metrics']['accuracy']
            assert metric['loss']==expected_row['metrics']['loss']
            # Trusted post-run oracle only. Export carry counts, never seed,
            # masks, raw updates or per-client carry details.
            carries=0;borrows=0
            for i in range(4):
                client=run/f'clients/C{i}'
                key=bytes.fromhex(json.loads((client/'client.json').read_text())['seed_key'])
                update=json.loads((client/f'audit/round-{row["round"]}.json').read_text())['update']
                masks=mask_words(key,row['round'],len(update))
                wire=[(int(q)+m)%65536 for q,m in zip(update,masks,strict=True)]
                chunks=[p['body'] for p in record['manifest']['inputs'] if p['sender']==f'C{i}']
                chunks.sort(key=lambda p:p['offset'])
                assert [v for p in chunks for v in p['values']]==wire
                carries+=sum(int(q)+m>=65536 for q,m in zip(update,masks,strict=True))
                borrows+=sum(int(q)+m<0 for q,m in zip(update,masks,strict=True))
            checks.append({'round':row['round'],'integer_sum_exact':True,'count_exact':True,
                           'model_bits_exact':True,'metrics_exact':True,
                           'wire_carry_coordinates':carries,'wire_borrow_coordinates':borrows,
                           'masked_wire_oracle_exact':True})
        public=Path('native')/run.name
        for name in ('verification.json','provenance.json','runtime-wall.json'):
            copy(run/name,public/name)
        for name in ('deployment.json','mpc/policy.json'):
            copy(run/name,public/name)
        for source in run.glob('attempt-*/runtime-bootstrap/guards/*.json'):
            copy(source,public/'runtime-guard'/source.name)
        (output/public/'public-results.json.gz').write_bytes(gzip.compress(paths[0].read_bytes(),mtime=0))
        for name,expected_hash in json.loads((run/'provenance.json').read_text())['source_sha256'].items():
            source=run/'sources'/name
            assert sha(source)==expected_hash
            copy(source,public/'sources'/name)
        for i in range(4): copy(run/f'mpc/P{i}/native.log',public/f'P{i}/native.log')
        # Public counters/certificates/model hashes; never client audit/seed/share.
        native_checks.append({'case':case,'seed':seed,'rounds':checks,
            'accuracy':body['metrics'][-1]['accuracy'],'source_run':run.name,
            'communication':verification['communication']['native'],
            'scope':verification['scope']})
    aggregate={'completed_oracle_conditions':len(reports),'seeds':config['seeds'],
               'groups':groups,'native_comparisons':native_checks,
               'scope':'poisoning effect and tested implementation correctness; not a privacy proof'}
    (output/'results.json').write_text(json.dumps(aggregate,ensure_ascii=False,indent=2)+'\n')
    if any(c['case']=='clean' and 'runtime-fix' in c['source_run'] for c in native_checks):
        diagnosis=output.parent/'seed-mpc-runtime-failure-2026-10-11.md'
        if diagnosis.exists():
            text=diagnosis.read_text().replace(
                'FMNIST 정상 조건은 별도 새 세션에서 5라운드 재실행 중이다.',
                'FMNIST 정상 조건은 별도 새 세션에서 5라운드 재실행과 독립 재학습 검증을 완료했으며, 모든 라운드의 정수 합·모델·평가값이 동일 평문 기준과 정확히 일치했다.')
            diagnosis.write_text(text)
    report=output.with_suffix('.md')
    if native_checks and report.exists():
        text=report.read_text()
        start=text.index('## Full LeNet5 실제 Flower + Rep4 비교')
        end=text.index('## 재현 자료·한계',start)
        labels={'clean':'정상','out-of-bound':'범위 밖 B+1','bounded-100':'범위 내 norm 한도 100%'}
        lines=[]
        for result in native_checks:
            costs=result['communication']
            lines.append(f'| {labels[result["case"]]} | {100*result["accuracy"]:.2f}% | 5/5 | {costs["setup_sent_bytes"]:,} | '+
                         ', '.join(f'{r["sent_bytes"]:,}' for r in costs['rounds'])+' |')
        carries=sum(r['wire_carry_coordinates'] for c in native_checks for r in c['rounds'])
        borrows=sum(r['wire_borrow_coordinates'] for c in native_checks for r in c['rounds'])
        section='## Full LeNet5 실제 Flower + Rep4 비교\n\n'
        section+=f'**검증 완료: {len(native_checks)}/3 조건.** 완료한 조건은 seed 42, 각 5라운드다. '+('나머지 조건은 순차 실행 중이다. ' if len(native_checks)<3 else '세 조건 모두 순차 실행과 독립 재학습 대조를 완료했다. ')
        section+='Norm 한도 100% 조건은 평문 3-seed 결과에서 가장 큰 평균 하락을 보여 선택했다. 완료한 모든 라운드의 정수 SUM/count, 모델 bits, accuracy/loss가 평문 동일 필터 및 독립 재학습 reference와 정확히 일치했다.\n\n'
        section+='| 조건 | 최종 정확도 | 라운드별 정확 일치 | 셋업 native 송신 bytes | r1~r5 native 송신 bytes |\n|---|---|---|---|---|\n'+'\n'.join(lines)+'\n\n'
        section+=f'실제 wire에서 Q를 넘는 carry 좌표 {carries:,}건과 음수 borrow 좌표 {borrows:,}건을 trusted post-run oracle로 확인했다. 해당 마스크된 wire와 signed 복원·집계 대조가 모두 일치했다. 이 좌표 수는 전체 완료 조건의 합계이며 seed/mask/raw 업데이트는 공개하지 않는다. 최종 SUM은 Q로 줄이지 않았다.\n\n'
        section+='Native 수치는 네 송신자 counter의 합이며 live preprocessing을 포함한다. TLS/TCP/IP/framing 및 upstream no_stats 전송은 제외한다. Flower 객체 그래프·RPC JSON·external seed socket은 각 verification JSON에서 별도로 확인하며 같은 전송을 중복 합산하지 않는다.\n\n'
        section+='최초 병렬 실행은 native 빌드와 겹쳐 7.29 GiB WSL 메모리의 95% 한도를 넘었고 Ray가 학습 worker를 종료했다. 해당 누락 라운드는 정상 비교 조건을 만족하지 않아 중단·보존하고 결과에서 제외했다. 완료 결과는 다른 학습/빌드와 겹치지 않는 새 세션의 순차 실행이다. 수집 마감은 60초에서 600초로 늘렸고 조기 전원 수집 확정은 유지했다. 이는 대기 설정이며 B/τ는 변경하지 않았다.\n\n'
        section+='첫 순차 정상 실행도 Flower/Ray의 직렬화 예외 후 actor pool 소진으로 3~5라운드가 abort하여 제외했다. 수정은 설치 라이브러리를 변경하지 않고 해당 실행의 source-hash로 고정한 process-local guard로 적용했다. 예외 시 actor를 반환하고, Ray pickle 준비 단계의 확인된 예외에만 bounded retry를 적용한다. 정상 조건은 새 세션 재실행 결과다. [오류 진단 및 수정](seed-mpc-runtime-failure-2026-10-11.md)을 참조한다.\n\n'
        section+='전체 모델 실행은 Flower Simulation/Ray와 같은 Unix UID의 trusted test harness다. 서버 메시지에는 masked 업데이트만 있고 평문 audit은 별도 post-run reference에만 사용하지만, 이 학습 실행을 독립 운영자 격리의 증거로 제시하지 않는다. 위 작은 Deployment의 역할 격리 결과와 구분한다.\n\n'
        report.write_text(text[:start]+section+text[end:])
    manifest={str(p.relative_to(output)):sha(p) for p in sorted(output.rglob('*'))
              if p.is_file() and p.name!='manifest.json'}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'oracle_conditions':len(reports),'native_runs':len(native_checks),'hashed_artifacts':len(manifest)}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle',type=Path,required=True)
    parser.add_argument('--native',type=Path,nargs='*',default=[])
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();export(args.oracle,args.native,args.output)

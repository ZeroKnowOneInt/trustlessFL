"""Read-only before/after validation and public ACK/collection cost report."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import re


def read(path): return json.loads(Path(path).read_text())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def raw(directory):
    files=list(directory.glob('runtime-results/run-*/results.json'))
    assert len(files)==1
    return read(files[0])


def plot(public,attack):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib import font_manager
    font=Path('/mnt/c/Windows/Fonts/malgun.ttf')
    if font.exists():
        font_manager.fontManager.addfont(str(font))
        plt.rcParams['font.family']=font_manager.FontProperties(fname=str(font)).get_name()
    plt.rcParams['axes.unicode_minus']=False
    fig,axes=plt.subplots(1,2,figsize=(8.5,3.6),layout='constrained')
    for ax,key,unit,title in zip(axes,('serverapp_seconds','tracked_payload_bytes'),(1,1e6),
                                ('5라운드 ServerApp 시간 (초)','5라운드 추적 payload (MB)')):
        values=[[r[side][key]/unit for r in attack] for side in ('before','after')]
        means=[statistics.mean(v) for v in values]; sd=[statistics.stdev(v) for v in values]
        ax.bar([0,1],means,yerr=sd,capsize=4,color=['#9aa4b2','#178579'],width=.55)
        for i,points in enumerate(values):
            ax.scatter([i-.06,i,i+.06],points,color='#263445',s=15,zorder=3)
            ax.text(i,means[i]+max(means)*.07,f'{means[i]:.1f}',ha='center')
        ax.set_xticks([0,1],['개선 전','개선 후']);ax.set_title(title,fontsize=11)
        ax.set_ylim(0,max(means)*1.25);ax.spines[['top','right']].set_visible(False)
    fig.suptitle('동일 FMNIST·LeNet5 공격 조건: 3 seeds 평균 ± 표본 SD',fontsize=12)
    fig.savefig(public/'before-after.png',dpi=170);plt.close(fig)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before',type=Path,required=True)
    parser.add_argument('--after',type=Path,required=True)
    parser.add_argument('--before-results',type=Path,default=Path('docs/reproduction/flower-cost-comparison-2026-10-12/results.json'))
    parser.add_argument('--after-results',type=Path,default=Path('docs/reproduction/flower-cost-improved-2026-10-12/results.json'))
    parser.add_argument('--dropout',type=Path,default=Path('.cache/ack-improvement-dropout-final-2026-10-12'))
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    before=read(args.before/'configuration.json'); after=read(args.after/'configuration.json')
    before_public=read(args.before_results); after_public=read(args.after_results)
    assert before_public['completed'] and after_public['completed']
    assert before_public['backend_pin']==after_public['backend_pin']
    dropout=read(args.dropout/'verification.json')
    assert dropout['passed'] and dropout['dropout_and_catchup_exact'] and dropout['all_client_ack_absence_progress']
    for key in ('trustlessfl/seed_mpc_dropout.py','trustlessfl/seed_mpc_client_app.py',
                'trustlessfl/seed_mpc_server_app.py','trustlessfl/seed_mpc_committee.py'):
        assert sha(args.dropout/'app'/key)==sha(root/key)==after['source_sha256'][key]
    test_log=root/'.cache/ack-improvement-targeted-final-tests-2026-10-12.log'
    test_summary=re.search(r'(\d+) passed,.*in ([\d.]+)s',test_log.read_text())
    assert test_summary and 'failed' not in test_log.read_text()
    tested=int(test_summary.group(1))
    before_runs={(r['seed'],r['case'],r['variant']):r for r in before_public['runs']}
    after_runs={(r['seed'],r['case'],r['variant']):r for r in after_public['runs']}
    for key in ('jobs','policy','training','versions','data_sha256','host'): assert before[key]==after[key]
    for key in ('trustlessfl/research_cost_flower.py','trustlessfl/seed_mpc_training.py',
                'trustlessfl/seed_mpc_poisoning_fixture.py','trustlessfl/seed_mpc_policy.py'):
        assert before['source_sha256'][key]==after['source_sha256'][key]
    rows=[]; exact_inputs=0
    for seed,case,variant in after['jobs']:
        if variant!='private-mpc': continue
        name=f'{seed}-{case}-{variant}'
        oldrun=before_runs[seed,case,variant]; newrun=after_runs[seed,case,variant]
        old=raw(args.before/name); new=raw(args.after/name)
        assert oldrun['verified'] and newrun['verified']
        assert old['models']==new['models'] and old['metrics']==new['metrics']
        assert [r['result_certificate']['body']['result'] for r in old['records']]==[
            r['result_certificate']['body']['result'] for r in new['records']]
        for client in range(4):
            for round_id in range(1,6):
                path=Path('clients')/f'C{client}'/'audit'/f'round-{round_id}.json'
                a=read(args.before/name/path); b=read(args.after/name/path)
                assert a['update']==b['update'] and a['model_hash']==b['model_hash']
                exact_inputs+=1
        for a,b in zip(oldrun['communication']['rounds'],newrun['communication']['rounds'],strict=True):
            assert a['native_player_sent_bytes']==b['native_player_sent_bytes']
        def summarize(run,result):
            comm=run['communication']['rounds']; timing=run['round_timings']
            return {'serverapp_seconds':run['serverapp_seconds'],
                'flower_cli_seconds':run['flower_cli_seconds'],
                'tracked_payload_bytes':sum(r['tracked_layer_payload_bytes'] for r in comm),
                'flower_server_to_clients_bytes':sum(r['flower_server_to_clients_bytes'] for r in comm),
                'native_player_sent_bytes':sum(r['native_player_sent_bytes'] for r in comm),
                'collection_seconds':sum(r['masked_upload_and_manifest_seconds'] for r in timing),
                'round_seconds':[sum(v for k,v in r.items() if k.endswith('_seconds')) for r in timing],
                'round_payload_bytes':[r['tracked_layer_payload_bytes'] for r in comm],
                'client_confirmed_rounds':result['client_confirmed_rounds'],
                'notification_status_counts':{s:sum(e['status']==s for e in result['commit_notifications'])
                                               for s in ('confirmed','missing','invalid')},
                'fresh_head_queries':sum(e.get('kind')=='head-query' for e in result['commit_notifications'])}
        rows.append({'seed':seed,'case':case,'before':summarize(oldrun,old),'after':summarize(newrun,new)})
    attack=[r for r in rows if r['case']=='norm-overflow']
    means={side:{key:statistics.mean(r[side][key] for r in attack) for key in (
        'serverapp_seconds','flower_cli_seconds','tracked_payload_bytes','flower_server_to_clients_bytes',
        'native_player_sent_bytes','collection_seconds')} for side in ('before','after')}
    reduction={key:100*(1-means['after'][key]/means['before'][key]) for key in means['before']}
    updated=after_public
    body={'completed':True,'conditions_equal':True,'exact_input_comparisons':exact_inputs,
        'models_sums_counts_metrics_equal':True,'native_player_bytes_equal':True,
        'attack_mean':means,'reduction_percent':reduction,'runs':rows,
        'previous_plaintext_comparison':before_public['headline_attack_cost'],
        'updated_plaintext_comparison':updated['headline_attack_cost'],
        'regression':{'targeted_tests':tested,'test_log_sha256':sha(test_log),
            'dropout_verification_sha256':sha(args.dropout/'verification.json'),
            'dropout_rounds':10,'all_client_ack_loss_progress':True,
            'full_suite_complete':False,'legacy_environment_failure':
            'test_full_domain_keys: external Aion/agent/Aion/SA_ClientAgent.py missing; full suite interrupted'},
        'scope':'same local WSL host; fresh full learning each arm; logical tracked payload, not TCP/TLS wire'}
    report=args.report.resolve(); public=report.with_suffix(''); public.mkdir(parents=True,exist_ok=True)
    plot(public,attack)
    (public/'results.json').write_text(json.dumps(body,ensure_ascii=False,indent=2)+'\n')
    text=['# ACK·동기화 비용 개선 결과','',
        '기존 ACK 회수 지연과 이력 재전송을 수정하고, 완전히 동일한 공개 입력 snapshot의 반복 검증을 줄였다. MPC 회로·출력·정적 바운더리·신뢰 모델은 그대로다. Flower Hub 게시 설정은 변경하지 않았다.','',
        '## 구현','',
        '- 학습 응답 수집 중과 committee RPC 대기 중에도 메인 스레드에서 ACK를 회수한다. RPC는 완료/실패를 확인하고 join한 뒤 진행하며 Grid를 작업 스레드에서 접근하지 않는다.',
        '- Commit TTL은 max(60초, deployment timeout)이다. ACK가 실패하거나 5초 이상 지연되면 제한된 빈도로 현재 durable head를 조회한다. nonce·node·session·client 서명과 서버가 보유한 결정/모델 hash가 모두 맞을 때만 전달 cursor를 전진시킨다.',
        '- ACK/head proof는 전달 최적화용이다. 악성 클라이언트가 자신의 cursor를 거짓으로 주장해도 다른 클라이언트나 QC/MPC 판정이 바뀌지 않는다. ACK는 quorum·다음 라운드·결과 적용의 전제 조건이 아니다.',
        '- 입력 snapshot 검증 cache는 committee 인스턴스당 최대 2개다. 전체 canonical transcript와 policy·registry·contract·session 등 보안 설정의 SHA-256 digest가 일치해야 한다. 처음 보는 내용은 서명·좌표 coverage·context를 모두 검증한다. mutable snapshot은 저장하지 않고 frozen context만 저장한다.',
        '- QC 서명·모델/부모 결정·round 순서·durable lock은 cache로 생략하지 않는다. 재시작/새 인스턴스는 처음부터 검증한다. 캐시는 SHA-256 충돌 저항성과 기존 로컬 실행 환경의 무결성을 전제로 한다.','',
        '## 동일 조건 재측정','',
        'FMNIST 전체 60,000/10,000개, LeNet5 61,706 parameters, 4 clients, 4 aggregators, 5 rounds, seed 42/43/44, static real L2≤5·coordinate≤20,000이다. 정상 seed42와 공격 3 seeds 각각 평문 평균·평문 bound·실제 MPC를 새 Flower 런타임에서 학습했다(12회/60 rounds). 기존 SGD 산출물을 시간 측정에 재사용하지 않았다. 공격은 C0의 norm≈10 업데이트다.','',
        '정상 seed42의 첫 평문 시간 측정은 중간 실험의 종료·정리와 겹쳤다. 정상 비용을 대표하는 배율로 사용하지 않으며, 아래 요약과 평문 대비 핵심 배율은 정리 완료 후 실행한 공격 3 seeds를 기준으로 한다.','',
        '| 공격 3 seeds 평균, 5 rounds | 개선 전 | 개선 후 | 감소 |',
        '|---|---:|---:|---:|']
    labels=[('serverapp_seconds','ServerApp 초',1),('flower_cli_seconds','Flower CLI 초',1),
        ('collection_seconds','수집·manifest 초',1),('tracked_payload_bytes','추적 payload MB',1e6),
        ('flower_server_to_clients_bytes','Flower 서버→클라이언트 MB',1e6),
        ('native_player_sent_bytes','MPC Player 4-party 송신 MB',1e6)]
    for key,label,unit in labels:
        text.append(f'| {label} | {means["before"][key]/unit:.2f} | {means["after"][key]/unit:.2f} | {reduction[key]:.1f}% |')
    text+=['',f'![비용 개선 전후]({public.name}/before-after.png)']
    old_ratio=before_public['headline_attack_cost']; new_ratio=after_public['headline_attack_cost']
    text+=['', '동일 입력·모델인 평문 bound 대비 ServerApp 시간 배율은 '+
        f'**{old_ratio["private_over_bound_serverapp_ratio_of_means"]:.2f}× → '+
        f'{new_ratio["private_over_bound_serverapp_ratio_of_means"]:.2f}×**다. 추적 payload 배율은 '+
        f'{old_ratio["private_over_bound_tracked_payload_ratio_of_means"]:.2f}× → '+
        f'{new_ratio["private_over_bound_tracked_payload_ratio_of_means"]:.2f}×다. 3 seeds 평균의 비율이며 개별 비율의 평균과 구분한다.']
    text+=['','ServerApp에는 초기 등록·평가·학습·수집·MPC·인증·모델 적용·통지가 포함된다. 준비/컴파일·사후 oracle 시간은 별도로 기록했다. 관측 payload는 Flower 논리 graph/RPC body/native Player 송신이며 TCP/TLS wire나 미추적 IPC 전체가 아니다. 각 링크에서 한 경계만 세었지만 Flower의 메시지 간 객체 중복 제거/캐시는 할인하지 않은 지표다.','',
        '## 라운드별 추세 및 ACK','',
        '| 조건/seed | 전→후 ServerApp 초 | 전 round 1~5 초 | 후 round 1~5 초 | 후 confirmed head C0~C3 |',
        '|---|---:|---|---|---|']
    for row in rows:
        a,b=row['before'],row['after']
        text.append(f'| {row["case"]}/{row["seed"]} | {a["serverapp_seconds"]:.2f}→{b["serverapp_seconds"]:.2f} | '+
            ' / '.join(f'{v:.2f}' for v in a['round_seconds'])+' | '+
            ' / '.join(f'{v:.2f}' for v in b['round_seconds'])+' | '+
            ' / '.join(str(b['client_confirmed_rounds'][f'C{i}']) for i in range(4))+' |')
    text+=['','마지막 ACK drain은 0.5초 best-effort이므로 마지막 round의 ACK가 모두 회수되는 것을 완료 조건으로 삼지 않는다. 오프라인 복귀자는 필요한 suffix 전체를 검증한다. 정상 경로의 비용 개선이 임의의 dropout 패턴에서도 같은 시간 절감을 보장하는 것은 아니다.','',
        '## 검증과 남은 비용','',
        f'- 개선 전·후 **{exact_inputs}개 client-round 정수 입력**, 모든 모델·SUM·count·정확도가 정확히 일치했다. 개선 후 평문 bound↔MPC 입력 일치도 별도로 확인했다.',
        f'- 관련 회귀 테스트 {tested}개 통과. cache 내용/서명/policy/registry/session 변조, QC 부족, nonce/node/signer/session/head 변조, ACK 유실 복구, RPC 실패 join을 포함한다.',
        '- 실제 Flower·Rep4 dropout 10 rounds에서 부분 제출·사전 dropout·전 클라이언트 commit ACK 유실·복귀·abort·±80,000 wide SUM을 oracle와 대조했다.',
        '- 저장소 전체 테스트는 외부 원본 Aion fixture 파일 부재로 실패 1건을 관측한 후 중단했다. 전체 성공을 주장하지 않는다. 관련 회귀 테스트와 실제 MPC 실험은 통과했다.',
        '- native MPC 송신량은 동일하다. 큰 모델/많은 clients에 대한 MPC 자체의 비용 문제는 남는다. 독립 물리 호스트의 배포/latency 검증과 전체 composition 프라이버시 증명을 대신하지 않는다.','',
        '[개선 후 평문 대비 비용 상세](flower-cost-improved-2026-10-12.md), '+
        '[이전 병목 진단](flower-cost-bottleneck-2026-10-12.md), '+
        f'[전후 비교 JSON]({public.name}/results.json).','',
        '```bash','.venv/bin/python -m experiments.export_flower_cost_improvement \\',
        '  --before .cache/flower-cost-comparison-2026-10-12-v2 \\',
        '  --after .cache/flower-cost-improved-2026-10-12-v2 \\',
        '  --report docs/reproduction/flower-cost-improvement-2026-10-12.md','```']
    report.write_text('\n'.join(text)+'\n')
    sources=['trustlessfl/seed_mpc_dropout.py','trustlessfl/seed_mpc_server_app.py',
        'trustlessfl/seed_mpc_client_app.py','trustlessfl/seed_mpc_committee.py',
        'tests/test_seed_mpc_dropout.py','experiments/export_flower_cost_improvement.py']
    manifest={'sources':{s:sha(root/s) for s in sources},'public_files':{str(p.relative_to(report.parent)):sha(p)
        for p in (report,public/'results.json',public/'before-after.png')}}
    (public/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'mean':means,'reduction_percent':reduction},indent=2))


if __name__=='__main__':main()

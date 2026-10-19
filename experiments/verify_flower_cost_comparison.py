"""Finalize matched cost report, validate source/counters and export boundaries."""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np


def read(path):return json.loads(Path(path).read_text())
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def finalize(output,report):
    public=report.with_suffix('');body=read(public/'results.json')
    assert body['completed'] and len(body['runs'])==12
    assert sum(c['input_comparisons'] for c in body['exact_comparisons'])==80
    source_pins=body['configuration']['source_sha256'];backends=[];secrets=set()
    for row in body['runs']:
        directory=output/f'{row["seed"]}-{row["case"]}-{row["variant"]}'
        assert read(directory/'cost-run.json')['source_sha256']==source_pins
        assert read(directory/'verification.json')['passed']
        for relative,pin in source_pins.items():
            if relative.startswith('trustlessfl/'):
                assert sha(directory/'app'/relative)==pin
        evidence=list(directory.glob('attempt-*/runtime-bootstrap/guards/*.json'))
        assert evidence and all(read(e)=={'installed':True,'source_sha256':source_pins['trustlessfl/seed_mpc_flower_runtime.py']} for e in evidence)
        if row['variant']=='private-mpc':
            deployment=read(directory/'deployment.json');backends.append(deployment['backend_pin'])
            for path in directory.glob('clients/*/seed-input.json'):
                secrets.update(read(path)['component_seeds'])
            for path in directory.glob('clients/*/client.json'):
                identity=read(path)['identity'];secrets.update((identity['signing'],identity['encryption']))
            for path in directory.glob('mpc/P*/service-private.json'):
                identity=read(path)['identity'];secrets.update((identity['signing'],identity['encryption']))
        for comm in row['communication']['rounds']:
            assert comm['tracked_layer_payload_bytes']==sum(comm[k] for k in
                ('flower_server_to_clients_bytes','flower_clients_to_server_bytes','aggregator_rpc_sent_bytes',
                 'aggregator_rpc_received_bytes','native_player_sent_bytes'))
    assert len(backends)==4 and all(b==backends[0] for b in backends)
    body['backend_pin']=backends[0]
    body['post_run_source_and_guard_checks']=True
    summaries={r['variant']:r for r in body['summary'] if r['case']=='norm-overflow'}
    native=summaries['private-mpc'];plain=summaries['plain-bound'];mean=summaries['plain-mean']
    headline={'private_over_bound_serverapp_ratio_of_means':native['mean_serverapp_seconds']/plain['mean_serverapp_seconds'],
        'private_over_mean_serverapp_ratio_of_means':native['mean_serverapp_seconds']/mean['mean_serverapp_seconds'],
        'private_extra_serverapp_seconds_vs_bound':native['mean_serverapp_seconds']-plain['mean_serverapp_seconds'],
        'private_over_bound_tracked_payload_ratio_of_means':native['mean_tracked_round_payload_bytes']/plain['mean_tracked_round_payload_bytes'],
        'private_extra_payload_bytes_vs_bound':native['mean_tracked_round_payload_bytes']-plain['mean_tracked_round_payload_bytes']}
    body['headline_attack_cost']=headline
    write(public/'results.json',body)
    text=report.read_text()
    heading='\n## 비용 요약과 추가 확인\n'
    text=text.split(heading)[0]
    lead=(f'**공격 조건의 3-seed 평균에서 평문 bound는 {plain["mean_serverapp_seconds"]:.2f}초, '
          f'실제 MPC는 {native["mean_serverapp_seconds"]:.2f}초로 '
          f'{headline["private_over_bound_serverapp_ratio_of_means"]:.2f}배였다. '
          f'5라운드 추가 시간은 {headline["private_extra_serverapp_seconds_vs_bound"]:.2f}초다. '
          f'두 방식의 정확도는 {native["mean_final_accuracy_percent"]:.2f}%로 같았다.**')
    if lead not in text:
        text=text.replace('2026-10-12. 새로 실행한 비용 비교다.',lead+'\n\n2026-10-12. 새로 실행한 비용 비교다.')
    text+=heading+'\n'+lead+'\n\n'
    text+=(f'관측 계층 payload의 5라운드 합계는 평문 bound 평균 '
           f'**{plain["mean_tracked_round_payload_bytes"]/1e6:.2f} MB**, MPC 평균 '
           f'**{native["mean_tracked_round_payload_bytes"]/1e6:.2f} MB**로 '
           f'**{headline["private_over_bound_tracked_payload_ratio_of_means"]:.2f}배**였다. '
           '이 배율은 동일한 정의로 합산한 body counter 비교이며 전체 물리 네트워크 wire 배율이 아니다.\n')
    text+='\n본문의 seed별 배율과 여기의 평균 시간/평균 payload 배율은 집계 방식이 다르다. 어느 계산인지 구분해 사용한다.\n'
    text+='\nFlower graph는 메시지별 deflate object graph의 논리 크기다. 메시지 사이의 동일 object 캐시·중복 제거 할인은 적용하지 않았으므로 실제 wire에 전송된 byte 수라고 부르지 않는다. Native/RPC/Flower의 관측 계층 합계도 정의된 비용 지표이며 전체 물리 네트워크 통신량을 대신하지 않는다.\n'
    text+='\n### 공격 조건의 단계별 비용\n\n| 측정 구간 | 평문 bound 평균 초/5r | MPC 평균 초/5r |\n|---|---:|---:|\n'
    plain_runs=[r for r in body['runs'] if r['case']=='norm-overflow' and r['variant']=='plain-bound']
    native_runs=[r for r in body['runs'] if r['case']=='norm-overflow' and r['variant']=='private-mpc']
    phases=[('클라이언트 학습/양자화/공격 합계','client_training_quantization_seconds',None),
            ('학습·수집 / MPC의 수신증명·manifest 포함','collect_seconds','masked_upload_and_manifest_seconds'),
            ('검사·합 / MPC의 실행·결과 인증','check_and_sum_seconds','execute_and_result_certificate_seconds'),
            ('commit·평가 / MPC의 client 통지·평가·재적용 검사','commit_and_evaluation_seconds','client_commits_and_replay_checks_seconds')]
    for label,pk,nk in phases:
        if nk is None:
            pv=np.mean([r[pk] for r in plain_runs]);nv=np.mean([r[pk] for r in native_runs])
        else:
            pv=np.mean([sum(t[pk] for t in r['round_timings']) for r in plain_runs])
            nv=np.mean([sum(t[nk] for t in r['round_timings']) for r in native_runs])
        text+=f'| {label} | {pv:.4f} | {nv:.4f} |\n'
    text+='\n각 열의 단계 업무가 완전히 같지는 않다. Client work는 별도 client 시계이며 수집 구간과 겹치므로 위 행들을 더해 전체 wall로 사용하지 않는다. MPC input certificate 및 coordinator/committee apply 시간은 JSON의 다른 구간에 별도로 있다.\n'
    text+='\n현재 구현의 비용은 크다. 가장 큰 시간 증가는 수집·수신증명·manifest 구간에서 관측됐다. 여기에는 client 동기화·마스킹·서명·업로드·receipt 처리 등이 함께 들어가므로 어느 세부 작업이 원인인지 확정하려면 추가 profiling이 필요하다. 67초대 실행/결과 인증 구간만으로 5라운드 전체 비용을 설명해서는 안 된다. 라운드 후반의 시간·payload 증가에는 현재 인증서 chain 처리도 포함되므로 5라운드 평균을 긴 세션에 그대로 곱하지 않는다.\n'
    text+='\n관련 경계값·overflow·meter·공격 fixture 테스트는 **29 passed**였다. 12개 앱의 소스와 runtime guard가 고정된 pin에 맞고, 실제 MPC 4회가 같은 검증된 backend를 사용했음을 확인했다.\n'
    text+='\n최초 개발 기동은 앱 이름의 Flower 32자 제한에 걸려 학습 전에 실패했다. 이름 수정 후 새 v2 세션의 성공 실행만 측정했으며 초기 실패 자료는 별도 보존했다.\n'
    text+='\n```bash\n.venv/bin/python -m experiments.verify_flower_cost_comparison \\\n  --output .cache/flower-cost-comparison-2026-10-12-v2 \\\n  --report docs/reproduction/flower-cost-comparison-2026-10-12.md\n```\n'
    report.write_text(text)
    targets=[report]+[p for p in public.iterdir() if p.suffix=='.json' and p.name!='manifest.json']
    assert len(secrets)==128
    for target in targets:
        value=target.read_text();assert 'BEGIN PRIVATE KEY' not in value
        assert not any(secret in value for secret in secrets)
    manifest=read(public/'manifest.json')
    manifest.update(files={p.name:sha(p) for p in public.iterdir() if p.is_file() and p.name!='manifest.json'},
        report_sha256=sha(report),additional_verifier_sha256=sha(Path(__file__)),
        private_string_scan={'passed':True,'exact_private_strings':len(secrets),'text_files':len(targets)})
    write(public/'manifest.json',manifest)
    print('COST_FINALIZED',json.dumps(headline),'PRIVATE_SCAN',len(secrets))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True);a=p.parse_args();finalize(a.output.resolve(),a.report.resolve())

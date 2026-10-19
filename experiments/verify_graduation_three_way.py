"""Independent per-client replay check using local trusted experiment artifacts.

Never imports client keys or seed-input files. Exports equality flags, not vectors.
"""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from experiments.run_seed_mpc_poisoning import attack,canonical,vector_hash,POLICY


def read(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(output,report):
    config=read(output/'configuration.json');checks=[];attack_norms=[];attack_maxima=[]
    for seed in config['seeds']:
        for case in config['cases']:
            directory=output/f'native-seed-{seed}-{case}'
            paths=list((directory/'runtime-results').glob('run-*/results.json'));assert len(paths)==1
            actual=read(paths[0]);oracle=read(output/'oracle'/f'seed-{seed}-{case}-m1.json')
            for r,record in enumerate(actual['records'],1):
                before=np.asarray(actual['models'][r-1],dtype=np.float64)
                input_model_hash=vector_hash(before)
                for slot in range(4):
                    # Oracle cache keys bind seed, round, slot, label-flip flag and exact model.
                    cache=output/'oracle/trusted-private-cache'/f'{seed}-{r}-{slot}-0-{input_model_hash}.npz'
                    with np.load(cache,allow_pickle=False) as data:q=data['q']
                    expected=canonical(attack(q,case,POLICY) if slot==0 else q.copy(),POLICY)
                    audit=read(directory/f'clients/C{slot}/audit/round-{r}.json')
                    observed=np.asarray(audit['update'],dtype=np.int64)
                    if not np.array_equal(expected,observed):raise ValueError('plain/MPC individual input mismatch')
                    if case=='norm-overflow' and slot==0:
                        norm=sum(int(v)**2 for v in observed)
                        maximum=int(np.max(np.abs(observed)))
                        assert maximum<=POLICY.coordinate_cap and norm>POLICY.squared_threshold
                        attack_norms.append(norm**.5/POLICY.scale);attack_maxima.append(maximum/POLICY.scale)
                    checks.append({'seed':seed,'case':case,'round':r,'client_slot':slot,'input_exact':True})
    public=report.with_suffix('')
    target=public/'input-equality.json'
    target.write_text(json.dumps({'passed':True,'client_round_comparisons':len(checks),'checks':checks,
        'attack_checks':{'count':len(attack_norms),'l2_radius_min':min(attack_norms),'l2_radius_max':max(attack_norms),'max_coordinate_abs':max(attack_maxima),'all_coordinate_valid_and_l2_invalid':True},
        'scope':'trusted post-run oracle comparison only; no keys/seeds read; vectors not exported'},indent=2)+'\n')
    result_path=public/'results.json';result=read(result_path)
    result['per_client_input_equality_verified']=True
    result['per_client_input_comparisons']=len(checks)
    result_path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    text=report.read_text()
    text+='\n## 추가 입력 대조\n\n'+f'별도 검증기에서 **{len(checks)}개 client-round 입력**을 로컬 private reference cache와 MPC client의 test audit 사이에 좌표별로 비교해 모두 일치했다. Seed·round·slot·현재 모델 hash로 cache를 선택했으며 keys/seed 파일은 읽지 않았다. '+f'[입력 일치 결과]({public.name}/input-equality.json).\n'
    text+=f'\n실제 공격 입력 {len(attack_norms)}건은 모두 좌표 상한 안에 있었다. L2 반경은 **{min(attack_norms):.5f}~{max(attack_norms):.5f}**(한도 5), 최대 좌표 절댓값은 **{max(attack_maxima):.5f}**(한도 2)였다. 따라서 이번 제외는 좌표 초과 대신 전체 norm 위반을 검사한 결과다.\n'
    report.write_text(text)
    manifest_path=public/'manifest.json';manifest=read(manifest_path)
    manifest['files']={str(f.relative_to(public)):sha(f) for f in public.iterdir() if f.is_file() and f.name!='manifest.json'}
    manifest['additional_verifier_sha256']=sha(Path(__file__))
    manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print('PER_CLIENT_INPUTS_EXACT',len(checks),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();verify(args.output.resolve(),args.report.resolve())

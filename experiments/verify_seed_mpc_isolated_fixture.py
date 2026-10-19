"""Verify a public isolated fixture without reading client secrets/audits."""
import argparse
import json
from pathlib import Path

from experiments.run_seed_mpc_flower import sha,verify_collection_receipts,verify_communication
from trustlessfl.seed_mpc_session import load_deployment
from trustlessfl.seed_mpc_training import fixture_update
from trustlessfl.crypto import canonical


def verify(root):
    deployment,committee=load_deployment(root/'deployment.json')
    if deployment['training']['mode']!='fixture' or not deployment['role_isolation'] or deployment['trusted_test_audit']:
        raise ValueError('Only public isolated fixture with audit disabled')
    provenance=json.loads((root/'provenance.json').read_text())
    for name,expected in provenance['source_sha256'].items():
        p=root/'app'/name if name.startswith('trustlessfl/') else root/'sources'/name
        assert sha(p)==expected
    for name,expected in provenance['mpc_source_sha256'].items():
        assert sha(root/'mpc/Programs/Source'/name)==expected
    for name,expected in deployment['artifacts'].items():assert sha(root/'mpc/Programs'/name)==expected
    paths=list((root/'runtime-results').glob('run-*/results.json'));assert len(paths)==1
    body=json.loads(paths[0].read_text());model=deployment['initial_model'];rows=[]
    receipts=verify_collection_receipts(committee,body['records'],body['collection_receipts'])
    assert len(body['records'])==3 and len(body['models'])==4 and body['models'][0]==model
    for r,record in enumerate(body['records'],1):
        assert record['manifest']['presence']==[1]*4
        updates=[fixture_update(i,r,committee.policy.dimension) for i in range(4)]
        keep=[all(abs(v)<=committee.policy.coordinate_cap for v in u) and sum(v*v for v in u)<=committee.policy.squared_threshold for u in updates]
        count=sum(keep)
        result={'status':'abort'} if count<2 else {'status':'ok','count':count,
            'sum':[sum(u[j] for u,k in zip(updates,keep) if k) for j in range(committee.policy.dimension)]}
        committee.check_certificate(record['input_certificate'],committee.input_body(record['manifest']))
        committee.check_certificate(record['result_certificate'],committee.result_body(record['manifest'],result,model))
        model=committee.next_model(model,result);assert body['models'][r]==model
        rows.append({'round':r,'result':result,'model_exact':True})
    assert not any((root/f'clients/C{i}/audit').exists() for i in range(4))
    communication=verify_communication(root,deployment,body)
    probes=json.loads((root/'isolation-probes.json').read_text())
    assert probes['cross_role_denials']==72 and probes['own_file_readable']
    result={'passed':True,'runtime':body['runtime'],'rows':rows,'raw_audits':False,
            'receipt_certificates':receipts,'isolation':probes,'communication':communication,
            'scope':'public fixture math, certificates, native/RPC counters and filesystem/PID isolation; trusted host admin; shared loopback'}
    (root/'public-fixture-verification.json').write_bytes(canonical(result))
    print(json.dumps({'passed':True,'rounds':3,'cross_role_denials':72,'receipt_certificates':receipts,
                      'rpc_endpoint_counts_exact':communication['rpc_endpoint_counts_exact']}))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();verify(args.output.resolve())

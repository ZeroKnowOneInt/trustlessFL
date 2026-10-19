"""Read-only historical diagnosis; replay on disposable copies of PUBLIC ledgers.

No key/seed files are read and no production validation is bypassed. Profile
data describes call counts/time only; old model and input audits stay private.
"""
import argparse
from collections import Counter
import cProfile
import hashlib
import json
from pathlib import Path
import pstats
import sqlite3
import time

import numpy as np

from trustlessfl.seed_mpc_committee import CoordinatorState
from trustlessfl.seed_mpc_dropout import synchronize
from trustlessfl.seed_mpc_session import load_deployment


def read(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,v):Path(p).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n')


def clone_state(source,destination,committee,initial):
    # SQLite backup preserves committed WAL contents without changing source.
    with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True) as src:
        with sqlite3.connect(destination) as dst:src.backup(dst)
    destination.chmod(0o600)
    return CoordinatorState(committee,destination,initial)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runs',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    root=a.runs.resolve();output=a.output.resolve();output.mkdir(parents=True,exist_ok=False,mode=0o700)
    histories=[]
    for directory in sorted(root.glob('*private-mpc')):
        result_path=next((directory/'runtime-results').glob('run-*/results.json'))
        r=read(result_path)
        histories.append({'run':directory.name,'confirmed':r['client_confirmed_rounds'],
            'notification_status_counts':dict(Counter(e['status'] for e in r['commit_notifications'])),
            'collection_seconds':[t['masked_upload_and_manifest_seconds'] for t in r['round_timings']],
            'client_sync':{f'C{i}':[read_trace for line in (directory/f'clients/C{i}/sync-public.jsonl').read_text().splitlines()
                                  if (read_trace:=json.loads(line))['action']=='train'] for i in range(4)},
            'result_sha256':sha(result_path)})
    directory=root/'42-norm-overflow-private-mpc'
    deployment,committee=load_deployment(directory/'deployment.json')
    result=read(next((directory/'runtime-results').glob('run-*/results.json')))
    source=directory/'clients/C1/model.sqlite'
    with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True) as db:
        source_head_before=db.execute('SELECT round,decision,model FROM head WHERE id=1').fetchone()
    target=source_head_before[0];assert target>=4
    model=np.asarray(result['models'][target],dtype=np.float64)
    trials=[]
    for prefix in (0,1,2,3,4):
        state=clone_state(source,output/f'replay-{prefix}.sqlite',committee,deployment['initial_model'])
        try:
            head_before=state.head();decisions=result['records'][:prefix]
            start=time.perf_counter();applied=synchronize(state,decisions,model,target);elapsed=time.perf_counter()-start
            assert applied==0 and state.head()==head_before
            trials.append({'prefix_decisions':prefix,'wall_seconds':elapsed,'applied_decisions':applied,'head_unchanged':True})
            print('REPLAY',prefix,round(elapsed,4),flush=True)
        finally:state.ledger.close()
    state=clone_state(source,output/'profile.sqlite',committee,deployment['initial_model'])
    profile=cProfile.Profile()
    try:
        start=time.perf_counter();profile.enable()
        assert synchronize(state,result['records'][:4],model,target)==0
        profile.disable();profile_seconds=time.perf_counter()-start
    finally:state.ledger.close()
    # Dumps contain function names/counters/times, never argument values.
    profile.dump_stats(str(output/'sync-replay.prof'))
    stats=pstats.Stats(profile);functions=[]
    for (filename,line,name),(primitive,calls,self_seconds,cumulative,callers) in stats.stats.items():
        functions.append({'file':filename,'line':line,'function':name,'calls':calls,
                          'primitive_calls':primitive,'self_seconds':self_seconds,'cumulative_seconds':cumulative})
    functions.sort(key=lambda r:r['cumulative_seconds'],reverse=True)
    selected=[r for r in functions if ('trustlessfl/' in r['file'] or r['function']=='deepcopy' or
                                     'verify' in r['function'] or 'encode' in r['function'])]
    with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True) as db:
        assert db.execute('SELECT round,decision,model FROM head WHERE id=1').fetchone()==source_head_before
    # Inspect local installed Flower implementation: original request expiry
    # is checked even when a reply was already stored, before fetching it.
    import flwr
    package=Path(flwr.__file__).parent
    utils=package/'server/superlink/linkstate/utils.py'
    body={'completed':True,'scope':'historical evidence + actual already-decided sync replay; original state unchanged; profiler overhead separate',
          'histories':histories,'trials':trials,'profile_seconds':profile_seconds,
          'top_cumulative_functions':functions[:30],'selected_functions':selected,
          'masked_chunks_per_round':len(result['records'][0]['manifest']['inputs']),
          'raw_manifest_bytes_per_round':[len(__import__('trustlessfl.crypto',fromlist=['canonical']).canonical(r['manifest'])) for r in result['records']],
          'client_target_round':target,'original_head_unchanged':True,
          'flower_ttl_source':str(utils),'flower_ttl_source_sha256':sha(utils),
          'profiler_sha256':sha(Path(__file__))}
    write(output/'diagnosis.json',body)
    print('COLLECTION_DIAGNOSIS_COMPLETED',output/'diagnosis.json',flush=True)


if __name__=='__main__':main()

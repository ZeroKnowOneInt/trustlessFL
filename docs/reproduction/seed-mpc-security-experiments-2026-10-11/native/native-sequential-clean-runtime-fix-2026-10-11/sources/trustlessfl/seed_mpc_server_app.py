"""Flower coordinator: signed masked uploads and certified aggregate only."""
import json
from pathlib import Path
import time

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.serverapp import Grid, ServerApp

from .crypto import ProtocolError,canonical,digest,verify
from .seed_mpc_committee import CoordinatorState
from .seed_mpc_session import load_deployment,committee_rpc
from .seed_mpc_training import evaluate,evaluate_lenet
from .seed_mpc_wire import RoundContext
from .seed_mpc_dropout import stream_replies,CommitNotifications
from .seed_mpc_meter import ApplicationMeter,MeteredGrid,global_partition

app=ServerApp()


def masked_packets(reply,committee,expected_client):
    if reply.has_error() or set(reply.content)!= {'wire'}: raise ProtocolError('masked client reply required')
    record=reply.content['wire']
    if set(record)!= {'envelopes'}: raise ProtocolError('raw delta or extra client metadata forbidden')
    packets=json.loads(record['envelopes'])
    if not isinstance(packets,list) or not packets: raise ProtocolError('empty masked reply')
    for packet in packets:
        body=verify(packet,committee.registry,sender=expected_client)
        if body.get('client_id')!=expected_client: raise ProtocolError('wrong Flower client input')
    return packets


def certify_submission(deployment,committee,submission,*,meter=None):
    def call(action,body):
        return committee_rpc(deployment,action,body,**({'meter':meter} if meter else {}))
    try: votes=call('collect',{'submission':submission})
    except ProtocolError:
        # All RPC futures finish before this query. Partial receipt state must
        # never be silently omitted; >=3 can be propagated to the fourth party.
        stored=call('submission',{'collection_hash':submission['collection_hash'],
                                                     'client_id':submission['client_id']})
        votes=[]
        for item in stored:
            if item is not None:
                if canonical(item['submission'])!=canonical(submission): raise ProtocolError('stored submission differs')
                votes.append(item['receipt'])
        if not votes: return None
    return committee.receipt_certificate(submission,votes)


@app.main()
def main(grid:Grid,context:Context):
    cfg=context.run_config; deployment,committee=load_deployment(cfg['deployment-file'])
    meter=ApplicationMeter() if deployment.get('communication_meter') else None
    if meter: grid=MeteredGrid(grid,meter)
    def call(action,body=None):
        return committee_rpc(deployment,action,body,**({'meter':meter} if meter else {}))
    output=Path(cfg['output-dir'])/f'run-{context.run_id}'; output.mkdir(parents=True,exist_ok=False)
    state=CoordinatorState(committee,output/'coordinator.sqlite',deployment['initial_model'],create=True)
    records=[]; models=[state.head()['model']]; wire_bytes=0; started=time.monotonic()
    metrics=[]; round_timings=[]; collection_receipts=[]; submission_status=[]; notifications=None
    def metric():
        if deployment['training']['mode'] in ('tiny-fmnist','fmnist-lenet5'):
            with np.load(deployment['test_data'],allow_pickle=False) as data:
                evaluator=evaluate_lenet if deployment['training']['mode']=='fmnist-lenet5' else evaluate
                return evaluator(np.asarray(state.head()['model'],dtype=np.float64),data['x'],data['y'])
        return {}
    def requests(content,kind,mapping):
        replies=list(grid.send_and_receive([Message(content,dst_node_id=node,message_type=kind) for node in mapping],timeout=deployment['timeout']))
        if len(replies)!=4 or any(reply.has_error() for reply in replies): raise ProtocolError('Flower clients rejected request')
        found={}
        for reply in replies:
            source=reply.metadata.src_node_id
            if source not in mapping or source in found: raise ProtocolError('duplicate/unmapped Flower reply')
            found[source]=reply
        return found
    try:
        nodes=list(grid.get_node_ids())
        if len(nodes)!=4: raise ProtocolError('four Flower nodes required')
        identities=requests(RecordDict(),'query.identity',nodes)
        mapping={}
        for node,reply in identities.items():
            packet=json.loads(reply.content['registration']['envelope']); client=packet['sender']
            if client not in committee.clients or client in mapping.values(): raise ProtocolError('invalid Flower identity mapping')
            slot=committee.clients.index(client)
            verify(packet,committee.registry,sender=client)
            if canonical(packet)!=canonical(committee.registrations[slot]): raise ProtocolError('Flower registration differs')
            mapping[node]=client
        requests(RecordDict(),'query.register',mapping)
        ready=call('ready')
        if any(item.get('registration_checked') is not True for item in ready): raise ProtocolError('unchecked registration')
        if committee.snapshot_version==2: notifications=CommitNotifications(grid,committee,mapping)
        metrics.append(metric())
        for r in range(1,deployment['rounds']+1):
            if meter: meter.scope=f'round-{r}'
            tick=time.monotonic(); timing={'round':r}
            head=state.head(); model=np.asarray(head['model'],dtype=np.float64)
            rc=RoundContext(committee.session_id,committee.epoch,r,digest(head['model']),committee.policy.policy_hash)
            if notifications: notifications.poll()
            if deployment.get('test_fault')=='uncertified-model' and r==1:
                model=model.copy(); model[0]+=1.0
            packets=[]
            receipts=None; prepare_kwargs={}
            if committee.snapshot_version==2:
                opened_at=time.monotonic()
                collections=call('collect-open',{'context':rc.__dict__,'parent_decision':head['decision']})
                cutoff=opened_at+committee.collection_window_ms/1000
                messages=[]; status={name:'missing' for name in committee.clients}; proofs={}
                for node,client in mapping.items():
                    content=RecordDict({'model':ArrayRecord([model]),'config':ConfigRecord({'round':r}),
                        'chain':ConfigRecord({'json':canonical(records[notifications.confirmed[client]:]).decode()})})
                    messages.append(Message(content,dst_node_id=node,message_type='train',
                                            ttl=max(.001,cutoff-time.monotonic())))
                for reply in stream_replies(grid,messages,max(0,cutoff-time.monotonic())):
                    node=reply.metadata.src_node_id
                    if node not in mapping: continue
                    client=mapping[node]
                    if reply.has_error(): status[client]='transport-error'; continue
                    try:
                        incoming=masked_packets(reply,committee,client)
                        submission=committee.submission(rc,head['decision'],client,incoming)
                    except (ProtocolError,KeyError,TypeError,ValueError):
                        status[client]='invalid-input'; continue
                    proof=certify_submission(deployment,committee,submission,**({'meter':meter} if meter else {}))
                    if proof is None: status[client]='late-no-receipt'; continue
                    packets.extend(incoming); proofs[client]=proof; status[client]='receipted'
                    wire_bytes+=len(canonical(dict(reply.content['wire'])))
                presence=[int(name in proofs) for name in committee.clients]
                receipts=[proofs[name] for name in committee.clients if name in proofs]
                # Local services remain the authority on deadlines. No absence
                # is declared early just because an error reply arrived quickly.
                if not all(presence):
                    deadline=max(item['deadline_ms'] for item in collections)
                    while time.time_ns()//1000000<deadline:
                        notifications.poll(); remaining=max(0,(deadline-time.time_ns()//1000000)/1000)
                        time.sleep(min(.02,remaining))
                submission_status.append({'round':r,'clients':status})
                collection_receipts.append({'round':r,'certificates':receipts})
                prepare_kwargs={'receipt_certificates':receipts}
            else:
                content=RecordDict({'model':ArrayRecord([model]),'config':ConfigRecord({'round':r})})
                replies=requests(content,'train',mapping)
                for node,reply in replies.items():
                    wire_bytes+=len(canonical(dict(reply.content['wire'])))
                    packets.extend(masked_packets(reply,committee,mapping[node]))
            manifest=committee.manifest(rc,head['decision'],packets,
                **({'presence':presence} if committee.snapshot_version==2 else {}))
            timing['masked_upload_and_manifest_seconds']=round(time.monotonic()-tick,3); tick=time.monotonic()
            votes=call('prepare',{'manifest':manifest,**prepare_kwargs})
            input_certificate=committee.certificate(committee.input_body(manifest),votes)
            timing['input_certificate_seconds']=round(time.monotonic()-tick,3); tick=time.monotonic()
            votes=call('execute',{'manifest':manifest,'input_certificate':input_certificate})
            result_certificate=committee.certificate(votes[0]['body'],votes)
            timing['execute_and_result_certificate_seconds']=round(time.monotonic()-tick,3); tick=time.monotonic()
            if not state.apply(manifest,input_certificate,result_certificate): raise ProtocolError('first apply failed')
            decided=call('decide',{'manifest':manifest,'result_certificate':result_certificate})
            if decided!=[True]*4: raise ProtocolError('committee decision incomplete')
            timing['coordinator_and_committee_apply_seconds']=round(time.monotonic()-tick,3); tick=time.monotonic()
            decision={'manifest':manifest,'input_certificate':input_certificate,'result_certificate':result_certificate}
            records.append(decision)
            model=np.asarray(state.head()['model'],dtype=np.float64)
            content=RecordDict({'decision':ConfigRecord({'json':canonical(decision).decode()}),'model':ArrayRecord([model])})
            # Clients verify the whole result chain before accepting the next model.
            if notifications:
                notifications.send(records,state.head()); notifications.poll()
            for expected_applied in (() if notifications else (True,False)):
                acks=requests(content,'query.commit',mapping)
                for node,reply in acks.items():
                    packet=json.loads(reply.content['ack']['envelope'])
                    body=verify(packet,committee.registry,sender=mapping[node])
                    expected={'protocol':'seed-mpc-client-commit-v1','session_id':committee.session_id,
                        'round_id':r,'decision':state.head()['decision'],'model_hash':digest(state.head()['model']),
                        'applied':expected_applied}
                    if canonical(body)!=canonical(expected): raise ProtocolError('client model acknowledgment differs')
            if state.apply(manifest,input_certificate,result_certificate): raise ProtocolError('duplicate coordinator update')
            models.append(state.head()['model']); metrics.append(metric())
            timing['client_commits_and_replay_checks_seconds']=round(time.monotonic()-tick,3)
            round_timings.append(timing)
            print(f'SEED_MPC_FLOWER round={r} status={result_certificate["body"]["result"]["status"]}',flush=True)
        if meter: meter.scope='shutdown'
        completed=call('finish')
        if any(item['head']!=state.head() or item['native_exit']!=0 for item in completed): raise ProtocolError('native session incomplete')
        if notifications:
            # Bounded best-effort drain only, never an all-client success condition.
            drain=time.monotonic()+.5
            while notifications.pending and time.monotonic()<drain:
                notifications.poll(); time.sleep(.02)
        result={'runtime':('Official Flower Deployment / isolated SuperNodes; flwr run' if deployment.get('role_isolation') else 'Official Flower Simulation Runtime / Ray; flwr run'), 'run_id':context.run_id,
            'scope':('local role filesystem/PID namespaces; trusted host administrator; static f<=1; not full BFT/composition proof' if deployment.get('role_isolation') else 'local single-UID functional integration; static f<=1; not operator isolation/full BFT/composition proof'),
            'dimension':committee.policy.dimension,'rounds':deployment['rounds'],'mode':deployment['training']['mode'],
            'records':records,'models':models,'metrics':metrics,'mapping':mapping,'masked_application_json_bytes':wire_bytes,
            'snapshot_version':committee.snapshot_version,'collection_receipts':collection_receipts,
            'submission_status':submission_status,'commit_notifications':notifications.events if notifications else [],
            'client_confirmed_rounds':notifications.confirmed if notifications else {},
            'client_ack_required':committee.snapshot_version==1,
            'internal_mb':completed[0]['internal_mb'],'compile_invocations':1,'seed_inputs_per_client':1,
            'native_resources':[item['resources'] for item in completed],
            'native_session_wall_seconds':[item['session_wall_seconds'] for item in completed],
            'round_timings':round_timings,
            'wall_seconds':round(time.monotonic()-started,3),'final_head':state.head()}
        if meter:
            result['communication']={'native':global_partition([item['communication'] for item in completed]),
                                     'application':meter.report()}
        (output/'results.json').write_bytes(canonical(result))
    except Exception:
        (output/'failed.json').write_bytes(canonical({'status':'aborted','completed_rounds':state.head()['round'],
            'model_hash':digest(state.head()['model']),'plaintext_fallback':False}))
        raise
    finally: state.ledger.close()

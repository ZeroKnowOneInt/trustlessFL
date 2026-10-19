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
from .seed_mpc_training import evaluate
from .seed_mpc_wire import RoundContext

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


@app.main()
def main(grid:Grid,context:Context):
    cfg=context.run_config; deployment,committee=load_deployment(cfg['deployment-file'])
    output=Path(cfg['output-dir'])/f'run-{context.run_id}'; output.mkdir(parents=True,exist_ok=False)
    state=CoordinatorState(committee,output/'coordinator.sqlite',deployment['initial_model'],create=True)
    records=[]; models=[state.head()['model']]; wire_bytes=0; started=time.monotonic()
    metrics=[]
    def metric():
        if deployment['training']['mode']=='tiny-fmnist':
            with np.load(deployment['test_data'],allow_pickle=False) as data:
                return evaluate(np.asarray(state.head()['model'],dtype=np.float64),data['x'],data['y'])
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
        ready=committee_rpc(deployment,'ready')
        if any(item.get('registration_checked') is not True for item in ready): raise ProtocolError('unchecked registration')
        metrics.append(metric())
        for r in range(1,deployment['rounds']+1):
            head=state.head(); model=np.asarray(head['model'],dtype=np.float64)
            if deployment.get('test_fault')=='uncertified-model' and r==1:
                model=model.copy(); model[0]+=1.0
            content=RecordDict({'model':ArrayRecord([model]),'config':ConfigRecord({'round':r})})
            replies=requests(content,'train',mapping)
            packets=[]
            for node,reply in replies.items():
                wire_bytes+=len(canonical(dict(reply.content['wire'])))
                packets.extend(masked_packets(reply,committee,mapping[node]))
            rc=RoundContext(committee.session_id,committee.epoch,r,digest(head['model']),committee.policy.policy_hash)
            manifest=committee.manifest(rc,head['decision'],packets)
            votes=committee_rpc(deployment,'prepare',{'manifest':manifest})
            input_certificate=committee.certificate(committee.input_body(manifest),votes)
            votes=committee_rpc(deployment,'execute',{'manifest':manifest,'input_certificate':input_certificate})
            result_certificate=committee.certificate(votes[0]['body'],votes)
            if not state.apply(manifest,input_certificate,result_certificate): raise ProtocolError('first apply failed')
            decided=committee_rpc(deployment,'decide',{'manifest':manifest,'result_certificate':result_certificate})
            if decided!=[True]*4: raise ProtocolError('committee decision incomplete')
            decision={'manifest':manifest,'input_certificate':input_certificate,'result_certificate':result_certificate}
            model=np.asarray(state.head()['model'],dtype=np.float64)
            content=RecordDict({'decision':ConfigRecord({'json':canonical(decision).decode()}),'model':ArrayRecord([model])})
            # Clients verify the whole result chain before accepting the next model.
            for expected_applied in (True,False):
                acks=requests(content,'query.commit',mapping)
                for node,reply in acks.items():
                    packet=json.loads(reply.content['ack']['envelope'])
                    body=verify(packet,committee.registry,sender=mapping[node])
                    expected={'protocol':'seed-mpc-client-commit-v1','session_id':committee.session_id,
                        'round_id':r,'decision':state.head()['decision'],'model_hash':digest(state.head()['model']),
                        'applied':expected_applied}
                    if canonical(body)!=canonical(expected): raise ProtocolError('client model acknowledgment differs')
            if state.apply(manifest,input_certificate,result_certificate): raise ProtocolError('duplicate coordinator update')
            records.append(decision); models.append(state.head()['model']); metrics.append(metric())
            print(f'SEED_MPC_FLOWER round={r} status={result_certificate["body"]["result"]["status"]}',flush=True)
        completed=committee_rpc(deployment,'finish')
        if any(item['head']!=state.head() or item['native_exit']!=0 for item in completed): raise ProtocolError('native session incomplete')
        result={'runtime':'Official Flower Simulation Runtime / Ray; flwr run', 'run_id':context.run_id,
            'scope':'local single-UID functional integration; static f<=1; not operator isolation/full BFT/composition proof',
            'dimension':committee.policy.dimension,'rounds':deployment['rounds'],'mode':deployment['training']['mode'],
            'records':records,'models':models,'metrics':metrics,'mapping':mapping,'masked_application_json_bytes':wire_bytes,
            'internal_mb':completed[0]['internal_mb'],'compile_invocations':1,'seed_inputs_per_client':1,
            'native_resources':[item['resources'] for item in completed],
            'wall_seconds':round(time.monotonic()-started,3),'final_head':state.head()}
        (output/'results.json').write_bytes(canonical(result))
    except Exception:
        (output/'failed.json').write_bytes(canonical({'status':'aborted','completed_rounds':state.head()['round'],
            'model_hash':digest(state.head()['model']),'plaintext_fallback':False}))
        raise
    finally: state.ledger.close()

"""Certified catch-up, streaming deadlines and nonblocking ACK semantics."""
from copy import deepcopy
from types import SimpleNamespace
import json

import numpy as np
import pytest

from trustlessfl.crypto import Identity,ProtocolError,canonical,digest
from trustlessfl.seed_mpc_committee import SeedCommittee,CoordinatorState
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_wire import RoundContext
from trustlessfl.seed_mpc_dropout import synchronize,stream_replies,CommitNotifications,with_progress,chain_messages
from trustlessfl.seed_mpc_client_app import require_certified_model
from trustlessfl.seed_mpc_training import dropout_fixture_update,dropout_test_schedule


@pytest.fixture
def chain():
    names=[*(f'C{i}' for i in range(4)),*(f'A{i}' for i in range(4))]
    ids={n:Identity.generate(n) for n in names}; policy=SeedMPCPolicy(2,4,20000,2500000000)
    execution=digest('dropout code')
    registrations=[ids[f'C{i}'].sign({'protocol':'seed-mpc-registration-v2','session_id':'dropout-test',
        'committee_epoch':1,'client_id':f'C{i}','slot':i,'key_handle':f'h{i}',
        'policy_hash':policy.policy_hash,'execution_hash':execution}) for i in range(4)]
    c=SeedCommittee(policy,'dropout-test',1,names[:4],names[4:],{n:v.public() for n,v in ids.items()},
                    registrations,execution,[0.0,0.0],snapshot_version=2)
    model=[0.0,0.0]; parent=digest({'genesis':c.contract}); records=[]; models=[model]
    schedules=[([1]*4,{'status':'ok','count':4,'sum':[4,8]}),
        ([1,1,0,0],{'status':'ok','count':2,'sum':[-2,-4]}),([1,0,0,0],{'status':'abort'}),
        ([1]*4,{'status':'ok','count':4,'sum':[-4,-8]}),([0]*4,{'status':'abort'})]
    for r,(presence,result) in enumerate(schedules,1):
        context=RoundContext(c.session_id,1,r,digest(model),policy.policy_hash)
        packets=[ids[f'C{i}'].sign(context.payload(policy,client_id=f'C{i}',key_handle=f'h{i}',values=[40000,50000]))
                 for i,p in enumerate(presence) if p]
        manifest=c.manifest(context,parent,packets,presence=presence)
        iq=c.certificate(c.input_body(manifest),[ids[f'A{i}'].sign(c.input_body(manifest)) for i in range(3)])
        body=c.result_body(manifest,result,model); rq=c.certificate(body,[ids[f'A{i}'].sign(body) for i in range(3)])
        records.append({'manifest':manifest,'input_certificate':iq,'result_certificate':rq})
        model=c.next_model(model,result); models.append(model); parent=digest(body)
    return c,ids,records,models


def test_returning_client_catches_up_absent_and_abort_rounds_without_new_keys(chain,tmp_path):
    c,_,records,models=chain; path=tmp_path/'client.sqlite'
    state=CoordinatorState(c,path,models[0],create=True)
    assert synchronize(state,records[:1],np.asarray(models[1]),1)==1
    state.ledger.close(); state=CoordinatorState(c,path,models[0])
    try:
        assert synchronize(state,records[1:4],np.asarray(models[4]),4)==3
        assert state.head()['round']==4 and state.head()['model']==models[4]
        require_certified_model(np.asarray(models[4]),state.head(),5)
        assert synchronize(state,records,np.asarray(models[5]),5)==1
        assert synchronize(state,records,np.asarray(models[5]),5)==0
    finally: state.ledger.close()


@pytest.mark.parametrize('fault',['gap','reverse','missing-tail','bad-parent','bad-model','float32','two-votes',
                                'wrong-session','wrong-input','extra-field','bool-round','future'])
def test_bad_catchup_chain_rejected_before_any_durable_transition(chain,tmp_path,fault):
    c,_,records,models=chain; records=deepcopy(records); model=np.asarray(models[4]); target=4
    if fault=='gap': records=[records[0],records[2],records[3]]
    else: records=records[:4]
    if fault=='reverse': records.reverse()
    if fault=='missing-tail': records=records[:3]
    if fault=='bad-parent': records[-1]['manifest']['parent_decision']='00'*32
    if fault=='bad-model': model=model.copy(); model[0]+=1
    if fault=='float32': model=model.astype(np.float32)
    if fault=='two-votes': records[-1]['result_certificate']['votes']=records[-1]['result_certificate']['votes'][:2]
    if fault=='wrong-session': records[-1]['manifest']['context']['session_id']='other'
    if fault=='wrong-input': records[-1]['manifest']['inputs'][0]['body']['values'][0]+=1
    if fault=='extra-field': records[-1]['raw_update']=[0,0]
    if fault=='bool-round': target=True
    if fault=='future': target=3
    state=CoordinatorState(c,tmp_path/'client.sqlite',models[0],create=True)
    try:
        with pytest.raises(ProtocolError): synchronize(state,records,model,target)
        assert state.head()['round']==0 and state.ledger.row(1) is None
    finally: state.ledger.close()


def test_old_commit_replay_does_not_roll_back_and_stale_training_refused(chain,tmp_path):
    c,_,records,models=chain; state=CoordinatorState(c,tmp_path/'client.sqlite',models[0],create=True)
    try:
        synchronize(state,records[:4],np.asarray(models[4]),4)
        assert synchronize(state,records[:1],np.asarray(models[1]),1)==0
        assert state.head()['round']==4
        with pytest.raises(ProtocolError): require_certified_model(np.asarray(models[1]),state.head(),2)
        changed=deepcopy(records[:1]); changed[0]['result_certificate']['body']['next_model_hash']='00'*32
        with pytest.raises(ProtocolError): synchronize(state,changed,np.asarray(models[1]),1)
        assert state.head()['round']==4
    finally: state.ledger.close()


class FakeGrid:
    def __init__(self): self.sent=[]; self.incoming=[]; self.clock=0.; self.batch=[]
    def push_messages(self,messages):
        ids=[]
        for message in messages:
            ids.append(f'm{len(self.sent)}'); self.sent.append(message)
        return ids
    def pull_messages(self,ids):
        incoming=[x for x in self.incoming if x.metadata.reply_to_message_id in ids]
        self.incoming=[x for x in self.incoming if x not in incoming]
        if not incoming and self.batch: incoming=self.batch.pop(0)
        return incoming
    def sleep(self,seconds): self.clock+=seconds


def response(message_id,node,packet=None,error=False):
    return SimpleNamespace(metadata=SimpleNamespace(reply_to_message_id=message_id,src_node_id=node),
        has_error=lambda:error,content={'ack':{'envelope':canonical(packet).decode()}} if packet else {})


def test_stream_yields_first_reply_without_waiting_for_missing_peer():
    grid=FakeGrid(); grid.batch=[[response('m0',10)]]
    stream=stream_replies(grid,[object(),object()],.1,clock=lambda:grid.clock,sleep=grid.sleep)
    first=next(stream); assert first.metadata.src_node_id==10 and grid.clock==0
    assert list(stream)==[] and grid.clock>=.1


def test_stream_drops_late_reply_and_rejects_unrequested_reply():
    grid=FakeGrid(); grid.batch=[[response('m0',10),response('m1',11)]]
    stream=stream_replies(grid,[object(),object()],.1,clock=lambda:grid.clock,sleep=grid.sleep)
    next(stream); grid.clock=.2; assert list(stream)==[]
    grid=FakeGrid(); grid.batch=[[response('not-requested',10)]]
    with pytest.raises(ProtocolError): list(stream_replies(grid,[object()],.1,clock=lambda:grid.clock,sleep=grid.sleep))


@pytest.mark.parametrize('fault',[None,'absent','error','wrong-signer','tamper','stale','wrong-node','extra-field','body-list','body-scalar'])
def test_commit_delivery_and_invalid_acks_never_gate_next_round(chain,fault):
    c,ids,records,models=chain; grid=FakeGrid(); n=CommitNotifications(grid,c,{10:'C0'})
    head={'round':1,'model':models[1],'decision':digest(records[0]['result_certificate']['body'])}
    n.send(records[:1],head)
    assert len(grid.sent)==1 and n.confirmed['C0']==0
    body={'protocol':'seed-mpc-client-head-v2','session_id':c.session_id,'round_id':1,
          'decision':head['decision'],'model_hash':digest(head['model'])}
    if fault=='stale': body['round_id']=0
    if fault=='body-list': body=[]
    if fault=='body-scalar': body=1
    signer='C1' if fault=='wrong-signer' else 'C0'; packet=ids[signer].sign(body)
    if fault=='tamper': packet['body']['model_hash']='00'*32
    reply=response('m0',11 if fault=='wrong-node' else 10,packet,error=fault=='error')
    if fault=='extra-field': reply.content['norm']=1
    if fault!='absent': grid.incoming=[reply]
    n.poll(); assert n.confirmed['C0']==(1 if fault is None else 0)
    head={'round':2,'model':models[2],'decision':digest(records[1]['result_certificate']['body'])}
    n.send(records[:2],head)
    sent=json.loads(grid.sent[-1].content['chain']['json'])
    assert len(sent)==(1 if fault is None else 2)


def test_dropout_fixture_schedule_and_signed_wide_sum_are_fixed():
    schedule=dropout_test_schedule(); expected=[[1]*4,[1,1,1,0],[1,1,0,0],[1]*4,[1]*4,
                                              [1,1,0,0],[1,0,0,0],[1]*4,[0]*4,[1]*4]
    for r,presence in enumerate(expected,1):
        actual=[int(schedule.get(str(r),{}).get(f'C{i}',{}).get('train') not in ('drop-before','timeout-before','partial')) for i in range(4)]
        assert actual==presence
        updates=[dropout_fixture_update(i,r,65) for i in range(4)]
        assert all(max(map(abs,u))<=20000 and sum(v*v for v in u)<=2500000000 for u in updates)
        if r==1: assert sum(u[0] for u in updates)==80000 and sum(u[-1] for u in updates)==-80000
    assert all(v['commit']=='drop' for v in schedule['5'].values())


@pytest.mark.parametrize('received',[0,1,2,3,4])
def test_collection_failure_recovers_quorum_or_fails_explicitly(chain,monkeypatch,received):
    import trustlessfl.seed_mpc_server_app as server
    c,ids,records,_=chain; manifest=records[0]['manifest']; context=RoundContext(**manifest['context'])
    submission=c.submission(context,manifest['parent_decision'],'C0',[manifest['inputs'][0]])
    stored=[{'submission':submission,'receipt':ids[f'A{i}'].sign(c.receipt_body(submission))}
            if i<received else None for i in range(4)]
    def rpc(deployment,action,payload):
        if action=='collect': raise ProtocolError('test timeout')
        assert action=='submission'; return stored
    monkeypatch.setattr(server,'committee_rpc',rpc)
    if received in (1,2):
        with pytest.raises(ProtocolError): server.certify_submission({},c,submission)
    elif received==0: assert server.certify_submission({},c,submission) is None
    else: c.check_receipt_certificate(submission,server.certify_submission({},c,submission))


def test_commit_notification_dispatch_never_waits_for_ack(chain):
    c,_,records,models=chain; grid=FakeGrid(); n=CommitNotifications(grid,c,{10:'C0',11:'C1'})
    n.send(records[:1],{'round':1,'model':models[1],'decision':digest(records[0]['result_certificate']['body'])})
    assert len(n.pending)==2 and n.events==[] and grid.clock==0


def test_rejoining_node_requires_fresh_client_proof(chain):
    from trustlessfl.seed_mpc_network_clients import authenticated_identity
    c,ids,_,_=chain; nonce='ab'*32; node=123
    body={'protocol':'seed-mpc-node-binding-v1','session_id':c.session_id,'client_id':'C0','node_id':node,'nonce':nonce}
    reply=SimpleNamespace(metadata=SimpleNamespace(src_node_id=node),has_error=lambda:False,
        content={'registration':{'envelope':canonical(c.registrations[0]).decode(),'proof':canonical(ids['C0'].sign(body)).decode()}})
    assert authenticated_identity(reply,c,node,nonce)=='C0'
    with pytest.raises(ProtocolError): authenticated_identity(reply,c,node,'cd'*32)
    with pytest.raises(ProtocolError): authenticated_identity(reply,c,node+1,nonce)
    reply.content['registration']['proof']=canonical(ids['C1'].sign(body)).decode()
    with pytest.raises(ProtocolError): authenticated_identity(reply,c,node,nonce)


def test_rejoining_node_updates_logical_mapping(chain,monkeypatch):
    from trustlessfl import seed_mpc_network_clients as network
    c,ids,_,_=chain; nonce='ab'*32
    monkeypatch.setattr(network.secrets,'token_hex',lambda _:nonce)
    class Grid:
        def get_node_ids(self): return [123]
        def send_and_receive(self,messages,timeout):
            body={'protocol':'seed-mpc-node-binding-v1','session_id':c.session_id,'client_id':'C0','node_id':123,'nonce':nonce}
            return [SimpleNamespace(metadata=SimpleNamespace(src_node_id=123),has_error=lambda:False,
                content={'registration':{'envelope':canonical(c.registrations[0]).decode(),'proof':canonical(ids['C0'].sign(body)).decode()}})]
    mapping={10:'C0'}
    changes=network.discover(Grid(),c,mapping,timeout=1)
    assert mapping=={123:'C0'} and changes[0]['old_nodes']==[10]


def test_delayed_commit_ack_survives_node_rebinding(chain):
    c,ids,records,models=chain; grid=FakeGrid(); mapping={10:'C0'}
    notifications=CommitNotifications(grid,c,mapping)
    head={'round':1,'model':models[1],'decision':digest(records[0]['result_certificate']['body'])}
    notifications.send(records[:1],head); mapping.clear(); mapping[123]='C0'
    body={'protocol':'seed-mpc-client-head-v2','session_id':c.session_id,'round_id':1,'decision':head['decision'],'model_hash':digest(head['model'])}
    grid.incoming=[response('m0',10,ids['C0'].sign(body))]
    notifications.poll(); assert notifications.confirmed['C0']==1


def test_dynamic_round_stream_accepts_new_node_reply():
    grid=FakeGrid(); discovered=False
    def discover():
        nonlocal discovered
        if not discovered:
            discovered=True; return [object()]
        return None
    grid.batch=[[response('m1',123)]]
    replies=list(stream_replies(grid,[object()],1,clock=lambda:grid.clock,sleep=grid.sleep,discover=discover))
    assert replies[0].metadata.src_node_id==123


def test_stream_collects_commit_ack_while_training_reply_is_pending(chain):
    c,ids,records,models=chain; grid=FakeGrid()
    n=CommitNotifications(grid,c,{10:'C0'})
    head={'round':1,'model':models[1],'decision':digest(records[0]['result_certificate']['body'])}
    n.send(records[:1],head)
    body={'protocol':'seed-mpc-client-head-v2','session_id':c.session_id,'round_id':1,
          'decision':head['decision'],'model_hash':digest(head['model'])}
    grid.incoming=[response('m0',10,ids['C0'].sign(body))]
    replies=list(stream_replies(grid,[object()],.1,clock=lambda:grid.clock,sleep=grid.sleep,progress=n.poll))
    assert replies==[] and n.confirmed['C0']==1 and grid.clock>=.1


@pytest.mark.parametrize('fault',[None,'nonce','node','session','signer','unknown-head','altered-model'])
def test_missing_ack_recovers_only_fresh_known_signed_head(chain,fault):
    c,ids,records,models=chain; grid=FakeGrid()
    n=CommitNotifications(grid,c,{10:'C0'},clock=lambda:grid.clock)
    head={'round':1,'model':models[1],'decision':digest(records[0]['result_certificate']['body'])}
    n.send(records[:1],head); grid.incoming=[response('m0',10,error=True)]; n.poll()
    assert n.confirmed['C0']==0
    n.recover(); message=grid.sent[-1]; assert message.metadata.message_type=='query.head'
    nonce=message.content['challenge']['nonce']
    n.recover(); assert len(grid.sent)==2  # one pending recovery per client
    body={'protocol':'seed-mpc-client-head-proof-v1','session_id':c.session_id,'node_id':10,
          'nonce':nonce,'round_id':1,'decision':head['decision'],'model_hash':digest(head['model'])}
    if fault=='nonce': body['nonce']='ff'*32
    if fault=='node': body['node_id']=11
    if fault=='session': body['session_id']='other'
    if fault=='unknown-head': body['round_id']=2
    if fault=='altered-model': body['model_hash']='00'*32
    signer='C1' if fault=='signer' else 'C0'
    grid.incoming=[response('m1',10,ids[signer].sign(body))]; n.poll()
    assert n.confirmed['C0']==(1 if fault is None else 0)
    n.send(records[:2],{'round':2,'model':models[2],'decision':digest(records[1]['result_certificate']['body'])})
    assert len(json.loads(grid.sent[-1].content['chain']['json']))==(1 if fault is None else 2)


def test_lost_ack_recovery_is_throttled_and_nonblocking(chain):
    c,_,records,models=chain; grid=FakeGrid(); n=CommitNotifications(grid,c,{10:'C0'},clock=lambda:grid.clock)
    n.send(records[:1],{'round':1,'model':models[1],'decision':digest(records[0]['result_certificate']['body'])})
    n.recover(); assert len(grid.sent)==1
    grid.clock=5.; n.recover(); assert len(grid.sent)==2
    grid.incoming=[response('m1',10,error=True)]; n.poll(); n.recover(); assert len(grid.sent)==2
    grid.clock=7.; n.recover(); assert len(grid.sent)==3 and n.confirmed['C0']==0


def test_rpc_progress_stays_on_caller_and_joins_on_error():
    import threading
    started=threading.Event(); release=threading.Event(); ended=threading.Event()
    caller=threading.get_ident(); callbacks=[]
    def operation():
        assert threading.get_ident()!=caller
        started.set(); release.wait(2); ended.set()
        raise ProtocolError('test RPC failed')
    def progress():
        assert threading.get_ident()==caller and started.is_set()
        callbacks.append(True); release.set()
    with pytest.raises(ProtocolError): with_progress(operation,progress,interval=.001)
    assert callbacks and ended.is_set()


@pytest.mark.parametrize('fault',['value','signature','bool-alias','policy','registry','session'])
def test_manifest_cache_never_accepts_changed_content_or_security_binding(chain,fault,monkeypatch):
    import trustlessfl.seed_mpc_committee as module
    c,_,records,_=chain; m=deepcopy(records[0]['manifest']); c._manifest_cache.clear()
    original=module.verify; calls=[]
    def verify(*args,**kwargs): calls.append(True); return original(*args,**kwargs)
    monkeypatch.setattr(module,'verify',verify)
    context=c.check_manifest(m); count=len(calls)
    assert count==4 and c.check_manifest(deepcopy(m))==context and len(calls)==count
    if fault=='value': m['inputs'][0]['body']['values'][0]+=1
    if fault=='signature': m['inputs'][0]['signature']='00'*64
    if fault=='bool-alias': m['presence'][0]=True
    if fault=='policy': c.policy=SeedMPCPolicy(2,4,19999,2500000000)
    if fault=='registry': c.registry['C0']=Identity.generate('C0').public()
    if fault=='session': c.session_id='other'
    with pytest.raises(ProtocolError): c.check_manifest(m)


def test_manifest_cache_is_bounded_and_does_not_cache_quorum_votes(chain,tmp_path):
    c,_,records,models=chain
    for record in records: c.check_manifest(record['manifest'])
    assert len(c._manifest_cache)==2
    state=CoordinatorState(c,tmp_path/'client.sqlite',models[0],create=True)
    changed=deepcopy(records[:4]); changed[-1]['result_certificate']['votes']=changed[-1]['result_certificate']['votes'][:2]
    try:
        with pytest.raises(ProtocolError): synchronize(state,changed,np.asarray(models[4]),4)
        assert state.head()['round']==0 and state.ledger.row(1) is None
    finally: state.ledger.close()


@pytest.mark.parametrize('kind',['train','query.commit'])
def test_large_dispatch_shares_identical_suffix_without_omitting_proofs(chain,kind):
    from trustlessfl.seed_mpc_meter import graph_size
    c,_,records,models=chain
    targets={i+10:f'C{i}' for i in range(100)}; cursors={name:0 for name in targets.values()}
    cursors['C99']=1
    messages=list(chain_messages(records[:2],models[2],targets,cursors,kind=kind,ttl=3600.,round_id=2))
    assert len(messages)==100
    assert len({id(m.content) for m in messages})==2
    assert len({m.metadata.dst_node_id for m in messages})==100
    for i,m in enumerate(messages):
        assert json.loads(m.content['chain']['json'])==records[(1 if i==99 else 0):2]
        assert np.array_equal(m.content['model'].to_numpy_ndarrays()[0],np.asarray(models[2]))
    # Logical payload metric still charges each message's full graph.
    assert graph_size(messages[0])==graph_size(messages[1])
    assert graph_size(messages[0])[0]>graph_size(messages[-1])[0]


@pytest.mark.parametrize('fault',[None,'hash','round','bool','stored-change'])
def test_material_reference_requires_own_durable_exact_input(chain,tmp_path,fault):
    from trustlessfl.seed_mpc_service import prepared_manifest
    c,_,records,models=chain;state=CoordinatorState(c,tmp_path/'owned.sqlite',models[0],create=True)
    try:
        decision=records[0];state.apply(decision['manifest'],decision['input_certificate'],decision['result_certificate'])
        r=1;h=digest(decision['manifest'])
        if fault=='hash':h='00'*32
        if fault=='round':r=2
        if fault=='bool':r=True
        if fault=='stored-change':
            changed=deepcopy(decision['manifest']);changed['inputs'][0]['body']['values'][0]+=1
            state.ledger.db.execute('UPDATE rounds SET manifest=? WHERE round=1',(canonical(changed).decode(),))
        if fault is not None:
            with pytest.raises(ProtocolError):prepared_manifest(state,r,h)
        else:
            fetched=prepared_manifest(state,r,h);assert fetched==decision['manifest']
            fetched['inputs'].clear()
            assert prepared_manifest(state,r,h)==decision['manifest']
    finally:state.ledger.close()

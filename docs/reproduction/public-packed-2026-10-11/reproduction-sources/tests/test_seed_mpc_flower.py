"""Flower boundary and client mask-reuse protection, plus local RPC limits."""
from copy import deepcopy
from pathlib import Path

import numpy as np
import pytest
from flwr.app import ArrayRecord,ConfigRecord,Message,RecordDict

from trustlessfl.crypto import Identity,ProtocolError,canonical,digest
from trustlessfl.seed_mpc_client_app import TrainingCalls,require_certified_model,accept_decision
from trustlessfl.seed_mpc_committee import SeedCommittee,CoordinatorState
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_server_app import masked_packets
from trustlessfl.seed_mpc_session import rpc
from trustlessfl.seed_mpc_training import DIMENSION,fixture_update,scale_fixture_update,quantize,train
from trustlessfl.seed_mpc_resources import read_resources
from trustlessfl.seed_mpc_wire import RoundContext


def test_client_retry_returns_exact_same_ciphertext_after_restart(tmp_path):
    path=tmp_path/'calls.sqlite'; calls=TrainingCalls(path,create=True)
    ctx=digest({'model':[0.0],'round':1}); wire=[{'signed':'fixed-public-mask'}]
    assert calls.reserve(1,ctx) is None
    calls.cache(1,ctx,wire); calls.close()
    recovered=TrainingCalls(path)
    try:
        assert recovered.reserve(1,ctx)==wire
        with pytest.raises(ProtocolError): recovered.reserve(1,digest({'model':[1.0]}))
        with pytest.raises(ProtocolError): recovered.cache(1,ctx,[{'signed':'new-mask'}])
    finally: recovered.close()


def test_uncertain_client_training_cannot_reuse_mask_after_restart(tmp_path):
    path=tmp_path/'calls.sqlite'; calls=TrainingCalls(path,create=True); ctx=digest('round')
    assert calls.reserve(1,ctx) is None; calls.close()
    recovered=TrainingCalls(path)
    try:
        with pytest.raises(ProtocolError): recovered.reserve(1,ctx)
    finally: recovered.close()
    with pytest.raises(ProtocolError): TrainingCalls(tmp_path/'missing.sqlite')


def test_two_client_call_connections_cannot_start_same_round(tmp_path):
    path=tmp_path/'calls.sqlite'; a=TrainingCalls(path,create=True); b=TrainingCalls(path)
    try:
        context=digest('same-round'); assert a.reserve(1,context) is None
        with pytest.raises(ProtocolError): b.reserve(1,context)
    finally: a.close(); b.close()


@pytest.mark.parametrize('fault',['model','dtype','shape','nan','repeat','skip','boolean'])
def test_client_refuses_uncertified_model_or_round(fault):
    head={'model':[0.0,1.0],'round':1}; model=np.array(head['model'],dtype=np.float64); r=2
    if fault=='model': model[0]=1.0
    if fault=='dtype': model=model.astype(np.float32)
    if fault=='shape': model=model.reshape(1,2)
    if fault=='nan': model[0]=np.nan
    if fault=='repeat': r=1
    if fault=='skip': r=3
    if fault=='boolean': r=True
    with pytest.raises(ProtocolError): require_certified_model(model,head,r)


def test_valid_float64_certified_model_passes():
    head={'model':[0.0,1.0],'round':1}
    require_certified_model(np.array(head['model'],dtype=np.float64),head,2)


@pytest.mark.parametrize('fault',[None,'missing','duplicate','wrong-round','wrong-input','two-votes','reordered'])
def test_independent_flower_verifier_binds_receipt_quorum_to_selected_input(packet_fixture,fault):
    from experiments.run_seed_mpc_flower import verify_collection_receipts
    c,ids,_=packet_fixture
    registrations=[ids[name].sign({**c.registrations[i]['body'],'protocol':'seed-mpc-registration-v2'})
                   for i,name in enumerate(c.clients)]
    c=SeedCommittee(c.policy,c.session_id,c.epoch,c.clients,c.aggregators,c.registry,
        registrations,c.execution_hash,[0.0,0.0],snapshot_version=2)
    context=RoundContext(c.session_id,c.epoch,1,digest([0.0,0.0]),c.policy.policy_hash)
    packets=[ids[name].sign(context.payload(c.policy,client_id=name,key_handle=c.handles[i],values=[40000,50000]))
             for i,name in enumerate(c.clients)]
    manifest=c.manifest(context,digest({'genesis':c.contract}),packets,presence=[1]*4)
    proofs=[]
    for name,packet in zip(c.clients,packets,strict=True):
        submission=c.submission(context,manifest['parent_decision'],name,[packet])
        proofs.append(c.receipt_certificate(submission,[ids[a].sign(c.receipt_body(submission)) for a in c.aggregators[:3]]))
    collections=[{'round':1,'certificates':proofs}]
    if fault=='missing': collections[0]['certificates']=proofs[:-1]
    if fault=='duplicate': collections[0]['certificates']=[proofs[0]]*4
    if fault=='wrong-round': collections[0]['round']=2
    if fault=='wrong-input':
        changed=ids['C0'].sign(context.payload(c.policy,client_id='C0',key_handle=c.handles[0],values=[40001,50000]))
        manifest=c.manifest(context,manifest['parent_decision'],[changed,*packets[1:]],presence=[1]*4)
    if fault=='two-votes': proofs[0]['votes']=proofs[0]['votes'][:2]
    if fault=='reordered': collections[0]['certificates']=list(reversed(proofs))
    if fault:
        with pytest.raises(ProtocolError): verify_collection_receipts(c,[{'manifest':manifest}],collections)
    else: assert verify_collection_receipts(c,[{'manifest':manifest}],collections)==4


@pytest.fixture
def packet_fixture():
    ids={name:Identity.generate(name) for name in [*(f'C{i}' for i in range(4)),*(f'A{i}' for i in range(4))]}
    p=SeedMPCPolicy(2,4,20000,400000000); execution=digest('code')
    registrations=[ids[f'C{i}'].sign({'protocol':'seed-mpc-registration-v1','session_id':'fixture',
        'committee_epoch':1,'client_id':f'C{i}','slot':i,'key_handle':f'h{i}','policy_hash':p.policy_hash,
        'execution_hash':execution}) for i in range(4)]
    c=SeedCommittee(p,'fixture',1,[f'C{i}' for i in range(4)],[f'A{i}' for i in range(4)],
        {name:identity.public() for name,identity in ids.items()},registrations,execution,[0.0,0.0])
    rc=RoundContext('fixture',1,1,digest([0.0,0.0]),p.policy_hash)
    packet=ids['C0'].sign(rc.payload(p,client_id='C0',key_handle='h0',values=[40000,50000]))
    return c,ids,packet


def reply(records):
    return Message(RecordDict(records),dst_node_id=1,message_type='train')


def test_masked_reply_accepts_only_signed_public_wire(packet_fixture):
    c,_,packet=packet_fixture
    message=reply({'wire':ConfigRecord({'envelopes':canonical([packet]).decode()})})
    assert masked_packets(message,c,'C0')==[packet]


@pytest.mark.parametrize('fault',['delta','extra-record','delta-hash','wrong-client','tamper','empty'])
def test_raw_update_and_unsigned_or_mapped_wrong_inputs_rejected(packet_fixture,fault):
    c,_,packet=packet_fixture; expected='C0'; packets=[deepcopy(packet)]
    records={'wire':ConfigRecord({'envelopes':canonical(packets).decode()})}
    if fault=='delta': records={'delta':ArrayRecord([np.array([1.0,2.0])])}
    if fault=='extra-record': records['meta']=ConfigRecord({'norm':1.0})
    if fault=='delta-hash': records['wire']['delta_sha256']=digest([1.0,2.0])
    if fault=='wrong-client': expected='C1'
    if fault=='tamper':
        packets[0]['body']['values'][0]+=1; records['wire']['envelopes']=canonical(packets).decode()
    if fault=='empty': records['wire']['envelopes']='[]'
    with pytest.raises(ProtocolError): masked_packets(reply(records),c,expected)


def test_local_service_connector_rejects_nonloopback_address():
    for url in ['https://example.com','http://0.0.0.0:8000','http://localhost:8000']:
        with pytest.raises(ProtocolError): rpc(url,'head',timeout=.01)


def decision_fixture(c,ids):
    rc=RoundContext('fixture',1,1,digest([0.0,0.0]),c.policy.policy_hash)
    packets=[ids[f'C{i}'].sign(rc.payload(c.policy,client_id=f'C{i}',key_handle=f'h{i}',values=[40000,50000])) for i in range(4)]
    m=c.manifest(rc,digest({'genesis':c.contract}),packets)
    iq=c.certificate(c.input_body(m),[ids[f'A{i}'].sign(c.input_body(m)) for i in range(3)])
    result={'status':'ok','count':4,'sum':[4,8]}
    body=c.result_body(m,result,[0.0,0.0]); rq=c.certificate(body,[ids[f'A{i}'].sign(body) for i in range(3)])
    return {'manifest':m,'input_certificate':iq,'result_certificate':rq},c.next_model([0.0,0.0],result)


@pytest.mark.parametrize('fault',['wrong-array','dtype','bad-quorum','bad-parent','malformed'])
def test_client_commit_rejects_before_durable_model_change(packet_fixture,tmp_path,fault):
    c,ids,_=packet_fixture; decision,model=decision_fixture(c,ids); model=np.asarray(model,dtype=np.float64)
    state=CoordinatorState(c,tmp_path/'client.sqlite',[0.0,0.0],create=True)
    if fault=='wrong-array': model[0]+=1
    if fault=='dtype': model=model.astype(np.float32)
    if fault=='bad-quorum': decision['result_certificate']['votes']=decision['result_certificate']['votes'][:2]
    if fault=='bad-parent': decision['manifest']['parent_decision']='00'*32
    if fault=='malformed': decision={}
    try:
        with pytest.raises(ProtocolError): accept_decision(state,decision,model)
        assert state.head()['round']==0 and state.head()['model']==[0.0,0.0]
    finally: state.ledger.close()


def test_client_commit_applies_once_and_duplicate_survives_restart(packet_fixture,tmp_path):
    c,ids,_=packet_fixture; decision,model=decision_fixture(c,ids); path=tmp_path/'client.sqlite'
    state=CoordinatorState(c,path,[0.0,0.0],create=True)
    try:
        assert accept_decision(state,decision,np.asarray(model))
        assert not accept_decision(state,decision,np.asarray(model))
    finally: state.ledger.close()
    recovered=CoordinatorState(c,path,[0.0,0.0])
    try:
        assert not accept_decision(recovered,decision,np.asarray(model))
        assert recovered.head()['model']==model
    finally: recovered.ledger.close()


def test_training_quantization_and_public_fixture_edges():
    p=SeedMPCPolicy(2,4,20000,400000000,scale=10000)
    assert quantize(np.array([.00015,-.00025],dtype=np.float64),p)==[1,-2]
    with pytest.raises(ProtocolError): quantize(np.array([3.0,0.0]),p)
    assert sum(fixture_update(i,1,65)[0] for i in range(4))==80000
    assert fixture_update(2,2,65)[0]==20001
    assert sum(v*v for v in fixture_update(3,2,65))>400000000


def test_tiny_fmnist_training_is_deterministic_and_170_parameters():
    x=np.random.default_rng(42).integers(0,256,size=(32,28,28),dtype=np.uint8)
    y=np.arange(32,dtype=np.uint8)%10; model=np.zeros(DIMENSION,dtype=np.float64)
    args=dict(seed=42,slot=1,round_id=2,epochs=1,batch_size=16,learning_rate=.05)
    a=train(model,x,y,**args); b=train(model,x,y,**args)
    assert a.shape==(170,) and a.dtype==np.float64 and np.array_equal(a,b) and np.any(a!=0)


def test_full_lenet_training_matches_existing_trainer_and_partial_batch(tmp_path):
    from trustlessfl.seed_mpc_training import initial_lenet,train_lenet,evaluate_lenet
    from trustlessfl.fmnist import FmnistTrainer,evaluate as reference_evaluate
    x=np.random.default_rng(42).integers(0,256,size=(65,28,28),dtype=np.uint8)
    y=np.arange(65,dtype=np.uint8)%10; vector=initial_lenet(42)
    np.savez_compressed(tmp_path/'train.npz',x=x,y=y)
    np.savez_compressed(tmp_path/'reference.npz',weights=vector)
    args=dict(seed=42,slot=2,round_id=1,epochs=1,batch_size=64,learning_rate=.01,momentum=.9,weight_decay=.0005)
    delta,meta=train_lenet(vector,x,y,**args)
    oracle=FmnistTrainer(tmp_path/'train.npz',tmp_path/'reference.npz',seed=42,epochs=1,batch_size=64,device='cpu')
    expected=oracle(np.zeros(61706,dtype=np.float64),2,.01,1)
    assert vector.shape==(61706,) and np.array_equal(vector,initial_lenet(42))
    assert np.array_equal(delta,expected) and np.any(delta!=0)
    assert meta['optimizer_steps']==2 and meta['rows']==65
    p=SeedMPCPolicy(61706,4,20000,2500000000,scale=10000)
    assert quantize(delta,p)==quantize(expected,p)
    actual=evaluate_lenet(vector+delta,x,y)
    reference=reference_evaluate(delta,vector,x,y)
    assert actual['accuracy']==reference['accuracy'] and actual['test_error_rate']==reference['test_error_rate']
    assert np.isfinite(actual['loss'])


def test_full_lenet_rejects_wrong_model_dtype():
    from trustlessfl.seed_mpc_training import lenet_model
    with pytest.raises(ProtocolError): lenet_model(np.zeros(61706,dtype=np.float32))


@pytest.mark.parametrize('dimension',[1024,4096,61706])
def test_dense_scale_fixture_exercises_global_selection_and_signed_wide_sum(dimension):
    rounds=[[scale_fixture_update(i,r,dimension) for i in range(4)] for r in (1,2,3)]
    selected=[[all(abs(v)<=20000 for v in u) and sum(v*v for v in u)<=2500000000 for u in updates] for updates in rounds]
    assert selected==[[True]*4,[True,True,False,False],[True,False,False,False]]
    assert all(len(u)==dimension for updates in rounds for u in updates)
    assert sum(u[0] for u in rounds[0])==80000>65536
    assert sum(u[-1] for u in rounds[0])==-80000<-65536
    assert sum(rounds[1][i][0] for i in (0,1))==-40000<-32768
    assert sum(rounds[1][i][-1] for i in (0,1))==40000>32768
    assert all(any(u[j] for u in rounds[0]) for j in range(dimension))
    bad=rounds[1][3]
    assert all(sum(v*v for v in bad[k:k+32])<=2500000000 for k in range(0,dimension,32))
    assert sum(v*v for v in bad)>2500000000
    assert rounds[1][2][-1]==20001


@pytest.mark.parametrize('fault',[None,'missing','failed'])
def test_resource_report_requires_successful_complete_process(tmp_path,fault):
    report=tmp_path/'time.txt'
    text='User time (seconds): 1.25\nSystem time (seconds): 0.75\nMaximum resident set size (kbytes): 40000\nExit status: 0\n'
    if fault=='missing': text=text.replace('Maximum resident set size (kbytes): 40000\n','')
    if fault=='failed': text=text.replace('Exit status: 0','Exit status: 1')
    report.write_text(text)
    if fault:
        with pytest.raises(ProtocolError): read_resources(report)
    else:
        assert read_resources(report)=={'peak_rss_kib':40000,'user_cpu_seconds':1.25,'system_cpu_seconds':.75,'exit_status':0}


@pytest.mark.parametrize('blocks',[1,4,8,16,32,64])
def test_runtime_wire_padding_matches_selected_native_chunk_size(blocks):
    # Framing must cover the signed payload exactly once, even across a tail.
    from trustlessfl.seed_mpc_committee import digest_words
    from trustlessfl.seed_mpc_policy import SeedMPCPolicy
    ids={name:Identity.generate(name) for name in [*(f'C{i}' for i in range(4)),*(f'A{i}' for i in range(4))]}
    policy=SeedMPCPolicy(65,4,20000,400000000)
    registrations=[ids[f'C{i}'].sign({'protocol':'seed-mpc-registration-v2','session_id':'packing',
        'committee_epoch':1,'client_id':f'C{i}','slot':i,'key_handle':f'h{i}',
        'policy_hash':policy.policy_hash,'execution_hash':digest('code')}) for i in range(4)]
    committee=SeedCommittee(policy,'packing',1,[f'C{i}' for i in range(4)],[f'A{i}' for i in range(4)],
        {name:identity.public() for name,identity in ids.items()},registrations,digest('code'),[0.0]*65,snapshot_version=2)
    context=RoundContext('packing',1,1,digest([0.0]*65),policy.policy_hash)
    rows=[[50000+i+j for j in range(65)] for i in range(4)]
    packets=[ids[f'C{i}'].sign(context.payload(policy,client_id=f'C{i}',key_handle=f'h{i}',
              values=row[offset:offset+32],offset=offset))
             for i,row in enumerate(rows) for offset in range(0,65,32)]
    manifest=committee.manifest(context,digest({'genesis':committee.contract}),packets,presence=[1]*4)
    stream=committee.runtime_round(manifest,chunk_blocks=blocks)
    padded=((65+blocks*8-1)//(blocks*8))*(blocks*8)
    assert stream[:10]==[2,1,*digest_words(digest(manifest)),1,1,1,1]
    assert len(stream)==10+4*padded
    for i,row in enumerate(rows):
        assert stream[10+i*padded:10+(i+1)*padded]==row+[0]*(padded-65)


@pytest.mark.parametrize('blocks',[0,-1,65,True,1.5])
def test_staging_rejects_invalid_simd_width_before_creating_workspace(tmp_path,blocks):
    from experiments.run_seed_mpc_flower import stage
    output=tmp_path/'never-created'
    with pytest.raises(ProtocolError,match='chunk blocks'):
        stage(output,tmp_path/'no-installation',chunk_blocks=blocks)
    assert not output.exists()

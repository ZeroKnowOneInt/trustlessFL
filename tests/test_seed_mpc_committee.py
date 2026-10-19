"""Adversarial public transcripts and crash recovery, not an MPC proof.

Fake processes below test the trusted-local checkpoint parser only. Native
cryptographic execution is checked separately by run_seed_mpc_certified.
"""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from trustlessfl.crypto import Identity, ProtocolError, digest, verify
from trustlessfl.seed_mpc_committee import (
    SeedCommittee, AggregatorGuard, CoordinatorState, digest_words,
)
from trustlessfl.seed_mpc_native import NativeCheckpointReader
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_wire import RoundContext


@pytest.fixture
def env(tmp_path):
    identities={name:Identity.generate(name) for name in [*(f'C{i}' for i in range(4)),*(f'A{i}' for i in range(4))]}
    registry={name:identity.public() for name,identity in identities.items()}
    policy=SeedMPCPolicy(3,4,20000,400000000)
    initial=[0.0]*3
    execution_hash=digest({'pinned-code':'fixture'})
    registrations=[identities[f'C{i}'].sign({'protocol':'seed-mpc-registration-v1',
        'session_id':'fixture','committee_epoch':1,'client_id':f'C{i}','slot':i,
        'key_handle':f'h{i}','policy_hash':policy.policy_hash,'execution_hash':execution_hash}) for i in range(4)]
    committee=SeedCommittee(policy,'fixture',1,[f'C{i}' for i in range(4)],
        [f'A{i}' for i in range(4)],registry,registrations,execution_hash,initial)
    guards=[AggregatorGuard(committee,identities[f'A{i}'],tmp_path/f'A{i}.sqlite',initial,create=True) for i in range(4)]
    coordinator=CoordinatorState(committee,tmp_path/'coordinator.sqlite',initial,create=True)
    state=SimpleNamespace(committee=committee,identities=identities,registry=registry,
        registrations=registrations,initial=initial,guards=guards,coordinator=coordinator,path=tmp_path)
    yield state
    for guard in guards:
        guard.ledger.close()
    state.coordinator.ledger.close()


def manifest(env,*,alter=0,round_id=None):
    head=env.coordinator.head()
    context=RoundContext('fixture',1,round_id or head['round']+1,digest(head['model']),env.committee.policy.policy_hash)
    packets=[]
    for i in range(4):
        row=[10+i+alter,20+i,30+i]
        for offset in (0,2):
            body=context.payload(env.committee.policy,client_id=f'C{i}',key_handle=f'h{i}',values=row[offset:offset+2],offset=offset)
            packets.append(env.identities[f'C{i}'].sign(body))
    return env.committee.manifest(context,head['decision'],packets)


def reserve(env,m):
    votes=[guard.prepare(m) for guard in env.guards]
    qc=env.committee.certificate(env.committee.input_body(m),votes)
    for guard in env.guards: guard.reserve(m,qc)
    return qc


def checked_certificate(env,m,result=None):
    # Unit-only stand-in for the trusted adapter call after a native CHECK.
    result=result or {'status':'ok','count':4,'sum':[40,80,120]}
    votes=[guard._postchecked_vote(m,result) for guard in env.guards]
    return env.committee.certificate(votes[0]['body'],votes)


def resign(env,packet,body):
    return env.identities[packet['sender']].sign(body)


def test_signed_chunks_are_canonical_and_detached_from_caller(env):
    m=manifest(env)
    packets=deepcopy(m['inputs'])
    context=RoundContext(**m['context'])
    rebuilt=env.committee.manifest(context,m['parent_decision'],list(reversed(packets)))
    assert rebuilt==m
    packets[0]['body']['values'][0]+=1
    assert env.committee.check_manifest(rebuilt)==context
    env.registry['A0']['signing']='00'*32
    env.registrations[0]['body']['key_handle']='other'
    assert env.committee.registry['A0']==env.identities['A0'].public()
    assert env.committee.handles[0]=='h0'
    assert env.committee.registrations[0]['body']['key_handle']=='h0'


@pytest.mark.parametrize('field,value',[
    ('key_handle','wrong'),('client_id','C1'),('offset',1),('dimension',4),('word_bits',32),
    ('dimension',3.0),
])
def test_signed_but_wrong_input_context_is_rejected(env,field,value):
    m=manifest(env); packet=m['inputs'][0]; body=deepcopy(packet['body']); body[field]=value
    m['inputs'][0]=resign(env,packet,body)
    with pytest.raises(ProtocolError): env.committee.check_manifest(m)


@pytest.mark.parametrize('field,value',[
    ('session_id','other'),('committee_epoch',2),('round_id',2),
    ('model_hash','00'*32),('policy_hash','00'*32),
])
def test_signed_chunk_cannot_change_snapshot_context(env,field,value):
    m=manifest(env); packet=m['inputs'][0]; body=deepcopy(packet['body']); body['context'][field]=value
    m['inputs'][0]=resign(env,packet,body)
    with pytest.raises(ProtocolError): env.committee.check_manifest(m)


def test_input_tamper_signature_missing_duplicate_and_order(env):
    m=manifest(env)
    tampered=deepcopy(m); tampered['inputs'][0]['body']['values'][0]+=1
    with pytest.raises(ProtocolError): env.committee.check_manifest(tampered)
    for inputs in (m['inputs'][1:],m['inputs']+[m['inputs'][0]],list(reversed(m['inputs']))):
        with pytest.raises(ProtocolError): env.committee.check_manifest({**m,'inputs':inputs})


@pytest.mark.parametrize('field,value',[
    ('session_id','other'),('slot',1),('execution_hash','00'*32),('policy_hash','00'*32),
    ('slot',0.0),('committee_epoch',True),
])
def test_signed_registration_binds_execution_session_policy_and_slot(env,field,value):
    registrations=list(deepcopy(env.committee.registrations))
    body={**registrations[0]['body'],field:value}; registrations[0]=env.identities['C0'].sign(body)
    with pytest.raises(ProtocolError):
        SeedCommittee(env.committee.policy,'fixture',1,env.committee.clients,env.committee.aggregators,
            env.committee.registry,registrations,env.committee.execution_hash,env.initial)


def test_duplicate_identity_and_initial_model_contract_rejected(env):
    registry=deepcopy(env.committee.registry); registry['A1']=registry['A0']
    with pytest.raises(ProtocolError):
        SeedCommittee(env.committee.policy,'fixture',1,env.committee.clients,env.committee.aggregators,
            registry,env.committee.registrations,env.committee.execution_hash,env.initial)
    with pytest.raises(ProtocolError):
        CoordinatorState(env.committee,env.path/'wrong.sqlite',[1.0,0.0,0.0],create=True)
    assert not (env.path/'wrong.sqlite').exists()


def test_certificate_requires_three_distinct_exact_votes(env):
    body=env.committee.input_body(manifest(env))
    votes=[env.identities[f'A{i}'].sign(deepcopy(body)) for i in range(4)]
    for bad in (votes[:2],votes[:2]+[votes[0]],votes[:2]+[env.identities['C0'].sign(body)],
                votes[:2]+[env.identities['A2'].sign({**body,'input_hash':'00'*32})],
                votes[:2]+[env.identities['A2'].sign({**body,'round_id':True})]):
        with pytest.raises(ProtocolError): env.committee.certificate(body,bad)
    qc=env.committee.certificate(body,votes[:3]); votes[0]['body']['input_hash']='00'*32
    env.committee.check_certificate(qc,body)


def test_one_bad_result_vote_cannot_certify_false_sum(env):
    m=manifest(env); reserve(env,m)
    good=checked_certificate(env,m)
    false_body=deepcopy(good['body']); false_body['result']['sum'][0]+=1
    false_body['next_model_hash']=digest(env.committee.next_model(env.initial,false_body['result']))
    evil=env.identities['A0'].sign(false_body)
    for body in (good['body'],false_body):
        with pytest.raises(ProtocolError):
            env.committee.certificate(body,[evil,*good['votes'][1:3]])
    forged=deepcopy(good); forged['body']=false_body
    with pytest.raises(ProtocolError): env.coordinator.apply(m,env.committee.certificate(
        env.committee.input_body(m),[env.guards[i].prepare(m) for i in range(4)]),forged)
    assert env.coordinator.head()['model']==env.initial


def test_quorum_intersection_and_durable_input_lock(env):
    a=manifest(env); b=manifest(env,alter=1)
    votes=[guard.prepare(a) for guard in env.guards[:3]]
    env.committee.certificate(env.committee.input_body(a),votes)
    for guard in env.guards[:3]:
        with pytest.raises(ProtocolError): guard.prepare(b)
    with pytest.raises(ProtocolError):
        env.committee.certificate(env.committee.input_body(b),[env.guards[3].prepare(b)])
    second=AggregatorGuard(env.committee,env.identities['A0'],env.path/'A0.sqlite',env.initial)
    try:
        assert second.prepare(a)==votes[0]
        with pytest.raises(ProtocolError): second.prepare(b)
    finally: second.ledger.close()


def test_execution_reservation_survives_crash_and_prevents_retry(env):
    m=manifest(env); qc=reserve(env,m)
    recovered=AggregatorGuard(env.committee,env.identities['A0'],env.path/'A0.sqlite',env.initial)
    try:
        assert recovered.ledger.row(1)['phase']=='running'
        with pytest.raises(ProtocolError): recovered.reserve(m,qc)
        with pytest.raises(ProtocolError): recovered.prepare(manifest(env,alter=1))
    finally: recovered.ledger.close()
    with pytest.raises(ProtocolError):
        AggregatorGuard(env.committee,env.identities['A1'],env.path/'A0.sqlite',env.initial)
    with pytest.raises(ProtocolError):
        CoordinatorState(env.committee,env.path/'lost.sqlite',env.initial)


def test_unreserved_result_and_conflicting_postcheck_vote_rejected(env):
    m=manifest(env); env.guards[0].prepare(m)
    with pytest.raises(ProtocolError): env.guards[0]._postchecked_vote(m,{'status':'abort'})
    reserve(env,m); qc=checked_certificate(env,m)
    repeated=env.guards[0]._postchecked_vote(m,qc['body']['result'])
    assert repeated==qc['votes'][0]
    with pytest.raises(ProtocolError): env.guards[0]._postchecked_vote(m,{'status':'abort'})


@pytest.mark.parametrize('abort',[False,True])
def test_apply_once_restart_abort_and_certificate_subset_chain(env,abort):
    m=manifest(env); iqc=reserve(env,m)
    qc=checked_certificate(env,m,{'status':'abort'} if abort else None)
    subset=env.committee.certificate(qc['body'],qc['votes'][:3])
    assert env.coordinator.apply(m,iqc,subset)
    for guard in env.guards: assert guard.accept(m,qc)
    assert all(guard.head()==env.coordinator.head() for guard in env.guards)
    assert env.coordinator.head()['decision']==digest(qc['body'])
    expected=env.initial if abort else [0.001,0.002,0.003]
    assert env.coordinator.head()['model']==expected
    assert not env.coordinator.apply(m,iqc,qc)
    for guard in env.guards: assert not guard.accept(m,subset)
    env.coordinator.ledger.close()
    env.coordinator=CoordinatorState(env.committee,env.path/'coordinator.sqlite',env.initial)
    assert not env.coordinator.apply(m,iqc,qc)
    next_manifest=manifest(env)
    for guard in env.guards: guard.prepare(next_manifest)
    assert next_manifest['parent_decision']==digest(qc['body'])


@pytest.mark.parametrize('bad_certificate',[None,{}, {'body':{},'votes':[]}, {'body':None,'votes':[]}])
def test_malformed_certificate_fails_closed(env,bad_certificate):
    m=manifest(env); iqc=reserve(env,m)
    with pytest.raises(ProtocolError): env.coordinator.apply(m,iqc,bad_certificate)
    with pytest.raises(ProtocolError): env.guards[0].accept(m,bad_certificate)
    assert env.coordinator.head()['round']==0


@pytest.mark.parametrize('field,value',[('parent_decision','00'*32),('model_hash','00'*32),('input_hash','00'*32),('next_model_hash','00'*32)])
def test_tampered_result_binding_cannot_apply(env,field,value):
    m=manifest(env); iqc=reserve(env,m); qc=checked_certificate(env,m)
    qc['body'][field]=value
    with pytest.raises(ProtocolError): env.coordinator.apply(m,iqc,qc)
    assert env.coordinator.head()['round']==0


def local_reader(env,lines):
    m=manifest(env); reserve(env,m)
    path=env.path/'owned-native.log'; path.write_text('\n'.join(lines)+'\n')
    process=SimpleNamespace(poll=lambda:0)
    reader=NativeCheckpointReader(env.guards[0],process,path)
    return m,reader


def marker(m):
    return 'SEED_MPC_CHECKED 1 '+' '.join(map(str,digest_words(digest(m))))


def test_pending_output_without_native_checkpoint_never_votes(env):
    _,reader=local_reader(env,['SEED_MPC_REG_CHECKED',*[f'SEED_MPC_PUBLIC {v}' for v in [1,4,40,80,120]]])
    reader.wait_registration()
    with pytest.raises(ProtocolError): reader.vote(manifest(env))
    assert env.guards[0].ledger.row(1)['result_vote'] is None


def test_local_checkpoint_binds_full_input_hash_and_durable_vote(env):
    m=manifest(env)
    _,reader=local_reader(env,['SEED_MPC_REG_CHECKED',*[f'SEED_MPC_PUBLIC {v}' for v in [1,4,40,80,120]],marker(m)])
    reader.wait_registration(); vote=reader.vote(m)
    assert verify(vote,env.committee.registry)['result']=={'status':'ok','count':4,'sum':[40,80,120]}
    assert env.guards[0].ledger.row(1)['phase']=='checked'


@pytest.mark.parametrize('fault',['no-registration','wrong-round','wrong-hash','incomplete','extra','abort-leak','bad-status','bad-count'])
def test_checkpoint_failure_never_releases_signature(env,fault):
    m=manifest(env); values=[1,4,40,80,120]; check=marker(m); prefix=['SEED_MPC_REG_CHECKED']
    if fault=='no-registration': prefix=[]
    if fault=='wrong-round': check=check.replace('CHECKED 1 ','CHECKED 2 ')
    if fault=='wrong-hash': check='SEED_MPC_CHECKED 1 0 0 0 0'
    if fault=='incomplete': values=values[:-1]
    if fault=='extra': values.append(0)
    if fault=='abort-leak': values=[0,0,1,0,0]
    if fault=='bad-status': values[0]=2
    if fault=='bad-count': values[1]=1
    _,reader=local_reader(env,[*prefix,*[f'SEED_MPC_PUBLIC {v}' for v in values],check])
    with pytest.raises(ProtocolError):
        reader.wait_registration(); reader.vote(m)
    assert env.guards[0].ledger.row(1)['result_vote'] is None


def test_output_before_registration_checkpoint_rejected(env):
    _,reader=local_reader(env,['SEED_MPC_PUBLIC 1','SEED_MPC_REG_CHECKED'])
    with pytest.raises(ProtocolError): reader.wait_registration()


def test_recovery_after_checked_vote_can_accept_certificate(env):
    m=manifest(env); iqc=reserve(env,m); qc=checked_certificate(env,m)
    recovered=AggregatorGuard(env.committee,env.identities['A0'],env.path/'A0.sqlite',env.initial)
    try:
        assert recovered.ledger.row(1)['phase']=='checked'
        assert recovered.accept(m,qc)
        assert not recovered.accept(m,qc)
        with pytest.raises(ProtocolError): recovered.reserve(m,iqc)
    finally: recovered.ledger.close()


@pytest.fixture
def v2(env):
    registrations=[env.identities[p['sender']].sign({**p['body'],'protocol':'seed-mpc-registration-v2'})
                   for p in env.committee.registrations]
    c=SeedCommittee(env.committee.policy,'fixture',1,env.committee.clients,env.committee.aggregators,
        env.registry,registrations,env.committee.execution_hash,env.initial,snapshot_version=2)
    return SimpleNamespace(committee=c,identities=env.identities,initial=env.initial)


def partial_manifest(v2,presence):
    c=v2.committee
    context=RoundContext('fixture',1,1,digest(v2.initial),c.policy.policy_hash)
    packets=[v2.identities[name].sign(context.payload(c.policy,client_id=name,key_handle=c.handles[i],
                values=[10+i,20+i,30+i])) for i,name in enumerate(c.clients) if presence[i]]
    return c.manifest(context,'00'*32,packets,presence=presence)


@pytest.mark.parametrize('pattern',range(16))
def test_v2_all_presence_patterns_have_canonical_rows_and_markers(v2,pattern):
    presence=[(pattern>>i)&1 for i in range(4)]
    m=partial_manifest(v2,presence); c=v2.committee
    c.check_manifest(m)
    assert m['protocol']=='seed-mpc-input-snapshot-v2'
    assert len(m['inputs'])==sum(presence)
    assert [item['slot'] for item in m['absent']]==[i for i,p in enumerate(presence) if not p]
    rows=c.wire_rows(m)
    for i,p in enumerate(presence): assert rows[i]==([10+i,20+i,30+i] if p else [0,0,0])
    stream=c.runtime_round(m)
    assert stream[:2]==[2,1] and stream[6:10]==presence
    assert len(stream)==10+4*32
    assert c.result_body(m,{'status':'abort'},v2.initial)['next_model_hash']==digest(v2.initial)


@pytest.mark.parametrize('presence',[None,[],[1]*3,[1]*5,[True,1,1,1],[1.0,1,1,1],
                                    [-1,1,1,1],[2,1,1,1],[2**32,1,1,1],[2**63,1,1,1]])
def test_v2_presence_requires_full_width_canonical_bits(v2,presence):
    context=RoundContext('fixture',1,1,digest(v2.initial),v2.committee.policy.policy_hash)
    with pytest.raises(ProtocolError): v2.committee.manifest(context,'00'*32,[],presence=presence)


def test_v2_absence_cannot_hide_payload_or_missing_present_chunks(v2):
    m=partial_manifest(v2,[1]*4); c=v2.committee; context=RoundContext(**m['context'])
    with pytest.raises(ProtocolError): c.manifest(context,m['parent_decision'],m['inputs'],presence=[0,1,1,1])
    with pytest.raises(ProtocolError): c.manifest(context,m['parent_decision'],m['inputs'][1:],presence=[1]*4)
    body=deepcopy(m['inputs'][0]['body']); body['values']=body['values'][:-1]
    inputs=[v2.identities['C0'].sign(body),*m['inputs'][1:]]
    with pytest.raises(ProtocolError): c.manifest(context,m['parent_decision'],inputs,presence=[1]*4)


@pytest.mark.parametrize('fault',['version','marker','presence','order','extra-field'])
def test_v2_snapshot_tampering_is_rejected(v2,fault):
    m=partial_manifest(v2,[0,1,0,1])
    if fault=='version': m['protocol']='seed-mpc-input-snapshot-v1'
    if fault=='marker': m['absent'][0]['key_handle']='wrong'
    if fault=='presence': m['presence'][0]=1
    if fault=='order': m['absent'].reverse()
    if fault=='extra-field': m['unexpected']=True
    with pytest.raises(ProtocolError): v2.committee.check_manifest(m)


def test_v2_result_cannot_claim_more_accepts_than_submissions(v2):
    m=partial_manifest(v2,[1,1,0,0])
    with pytest.raises(ProtocolError): v2.committee.result_body(m,{'status':'ok','count':3,'sum':[0,0,0]},v2.initial)
    assert v2.committee.result_body(m,{'status':'ok','count':2,'sum':[0,0,0]},v2.initial)['result']['count']==2


def test_v1_and_v2_registrations_and_snapshots_are_not_interchangeable(env,v2):
    with pytest.raises(ProtocolError): env.committee.check_manifest(partial_manifest(v2,[1]*4))
    with pytest.raises(ProtocolError): v2.committee.check_manifest(manifest(env))
    with pytest.raises(ProtocolError):
        SeedCommittee(env.committee.policy,'fixture',1,env.committee.clients,env.committee.aggregators,
            env.registry,env.registrations,env.committee.execution_hash,env.initial,snapshot_version=2)
    m=manifest(env)
    with pytest.raises(ProtocolError):
        env.committee.manifest(RoundContext(**m['context']),m['parent_decision'],m['inputs'],presence=[1]*4)

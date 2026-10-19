"""Receipt/close safety with durable storage, not a BFT liveness proof."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Barrier,Event
from types import SimpleNamespace

import pytest

from trustlessfl.crypto import Identity,ProtocolError,digest,verify
from trustlessfl.seed_mpc_committee import SeedCommittee,AggregatorGuard
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_service import LocalAggregator
from trustlessfl.seed_mpc_wire import RoundContext


@pytest.fixture
def env(tmp_path):
    ids={name:Identity.generate(name) for name in [*(f'C{i}' for i in range(4)),*(f'A{i}' for i in range(4))]}
    registry={name:identity.public() for name,identity in ids.items()}
    policy=SeedMPCPolicy(3,4,20000,400000000); initial=[0.0]*3; execution=digest('receipt fixture')
    registrations=[ids[f'C{i}'].sign({'protocol':'seed-mpc-registration-v2','session_id':'receipt-fixture',
        'committee_epoch':1,'client_id':f'C{i}','slot':i,'key_handle':f'h{i}',
        'policy_hash':policy.policy_hash,'execution_hash':execution}) for i in range(4)]
    c=SeedCommittee(policy,'receipt-fixture',1,[f'C{i}' for i in range(4)],[f'A{i}' for i in range(4)],
        registry,registrations,execution,initial,snapshot_version=2,collection_window_ms=100)
    clock=[100000]
    guards=[AggregatorGuard(c,ids[f'A{i}'],tmp_path/f'A{i}.sqlite',initial,create=True,
                            clock_ms=lambda:clock[0]) for i in range(4)]
    head=guards[0].head(); ctx=RoundContext(c.session_id,1,1,digest(initial),policy.policy_hash)
    opened=[g.open_collection(ctx,head['decision']) for g in guards]
    state=SimpleNamespace(c=c,ids=ids,initial=initial,guards=guards,clock=clock,ctx=ctx,
                          parent=head['decision'],opened=opened,path=tmp_path)
    yield state
    for g in guards: g.ledger.close()


def bundle(env,presence=None,alter=0):
    presence=[1]*4 if presence is None else presence
    packets=[]; submissions=[]
    for i,client in enumerate(env.c.clients):
        if not presence[i]: continue
        row=[10+i+alter,20+i,30+i]; chunks=[]
        for offset in (0,2):
            body=env.ctx.payload(env.c.policy,client_id=client,key_handle=env.c.handles[i],
                                 values=row[offset:offset+2],offset=offset)
            chunks.append(env.ids[client].sign(body))
        packets.extend(chunks)
        submissions.append(env.c.submission(env.ctx,env.parent,client,chunks))
    return env.c.manifest(env.ctx,env.parent,packets,presence=presence),submissions


def receipts(env,submissions,guards=None):
    guards=env.guards if guards is None else guards
    return [env.c.receipt_certificate(s,[g.receive(s) for g in guards]) for s in submissions]


def test_receipt_is_complete_canonical_and_durable_before_release(env):
    _,subs=bundle(env,[1,0,0,0]); s=subs[0]; g=env.guards[0]
    vote=g.receive(s)
    assert verify(vote,env.c.registry)==env.c.receipt_body(s)
    reopened=AggregatorGuard(env.c,env.ids['A0'],env.path/'A0.sqlite',env.initial,clock_ms=lambda:env.clock[0])
    try:
        assert reopened.fetch_submission(s['collection_hash'],'C0')=={'submission':s,'receipt':vote}
        assert reopened.receive(s)==vote
    finally: reopened.ledger.close()
    s['inputs'][0]['body']['values'][0]=65535
    assert g.fetch_submission(env.opened[0]['collection_hash'],'C0')['submission']['inputs'][0]['body']['values'][0]==10


@pytest.mark.parametrize('fault',['partial','tamper','duplicate','wrong-handle','wrong-parent','wrong-model','extra-field'])
def test_invalid_submission_never_gets_receipt_or_poison_other_clients(env,fault):
    _,subs=bundle(env); s=deepcopy(subs[0]); g=env.guards[0]
    if fault=='partial': s['inputs']=s['inputs'][:-1]
    if fault=='tamper': s['inputs'][0]['body']['values'][0]+=1
    if fault=='duplicate': s['inputs'].append(s['inputs'][0])
    if fault=='wrong-handle': s['key_handle']='wrong'
    if fault=='wrong-parent': s['parent_decision']='00'*32
    if fault=='wrong-model': s['context']['model_hash']='00'*32
    if fault=='extra-field': s['deadline_ms']=env.clock[0]+1000
    with pytest.raises(ProtocolError): g.receive(s)
    assert g.fetch_submission(env.opened[0]['collection_hash'],'C0') is None
    assert g.receive(subs[1])['body']['client_id']=='C1'


def test_conflicting_signed_input_cannot_replace_committed_receipt(env):
    _,a=bundle(env,[1,0,0,0]); _,b=bundle(env,[1,0,0,0],alter=1)
    vote=env.guards[0].receive(a[0])
    with pytest.raises(ProtocolError): env.guards[0].receive(b[0])
    assert env.guards[0].receive(a[0])==vote


def test_subset_close_waits_for_local_deadline(env):
    m,subs=bundle(env,[1,1,0,0]); proof=receipts(env,subs); g=env.guards[0]
    with pytest.raises(ProtocolError,match='window still open'): g.prepare(m,proof)
    assert g.ledger.collection(env.opened[0]['collection_hash'])['phase']=='open'
    env.clock[0]+=100
    vote=g.prepare(m,proof)
    assert g.ledger.collection(env.opened[0]['collection_hash'])['phase']=='closed'
    assert g.prepare(m,proof)==vote
    assert g.ledger.db.execute('SELECT certificates FROM collection_proofs WHERE round=1').fetchone()[0]


def test_complete_roster_can_close_early_and_cached_receipt_remains_queryable(env):
    m,subs=bundle(env); proof=receipts(env,subs)
    original=env.guards[0].receive(subs[0]); env.guards[0].prepare(m,proof)
    env.clock[0]+=1000
    assert env.guards[0].receive(subs[0])==original
    assert env.guards[0].fetch_submission(subs[0]['collection_hash'],'C0')['receipt']==original


def test_close_rejects_new_receipt_even_for_input_already_in_snapshot(env):
    m,subs=bundle(env); proof=receipts(env,subs,env.guards[1:])
    env.guards[0].prepare(m,proof)
    with pytest.raises(ProtocolError,match='closed or expired'): env.guards[0].receive(subs[0])
    assert env.guards[0].fetch_submission(subs[0]['collection_hash'],'C0') is None


def test_deadline_and_restart_cannot_extend_collection_or_mint_late_receipt(env):
    _,subs=bundle(env,[1,0,0,0]); env.clock[0]+=100
    with pytest.raises(ProtocolError,match='closed or expired'): env.guards[0].receive(subs[0])
    recovered=AggregatorGuard(env.c,env.ids['A0'],env.path/'A0.sqlite',env.initial,clock_ms=lambda:env.clock[0])
    try:
        assert recovered.open_collection(env.ctx,env.parent)['deadline_ms']==env.opened[0]['deadline_ms']
        with pytest.raises(ProtocolError): recovered.receive(subs[0])
    finally: recovered.ledger.close()


def test_present_input_requires_quorum_receipt_not_just_payload(env):
    m,subs=bundle(env)
    for proof in (None,[],[env.c.certificate(env.c.receipt_body(subs[0]),[env.ids[f'A{i}'].sign(env.c.receipt_body(subs[0])) for i in range(3)])]):
        with pytest.raises(ProtocolError): env.guards[0].prepare(m,proof)
    assert env.guards[0].ledger.row(1) is None


@pytest.mark.parametrize('fault',['two-votes','duplicate','client-vote','wrong-hash','wrong-round','wrong-model','wrong-parent','float-round'])
def test_receipt_certificate_cannot_be_forged_or_replayed(env,fault):
    _,subs=bundle(env,[1,0,0,0]); s=subs[0]; proof=receipts(env,subs)[0]
    if fault=='two-votes': proof['votes']=proof['votes'][:2]
    elif fault=='duplicate': proof['votes']=[proof['votes'][0]]*3
    elif fault=='client-vote': proof['votes'][0]=env.ids['C0'].sign(proof['body'])
    else:
        body=deepcopy(proof['body'])
        if fault=='wrong-hash': body['submission_hash']='00'*32
        if fault=='wrong-round': body['context']['round_id']=2
        if fault=='float-round': body['context']['round_id']=1.0
        if fault=='wrong-model': body['context']['model_hash']='00'*32
        if fault=='wrong-parent': body['parent_decision']='00'*32
        proof={'body':body,'votes':[env.ids[f'A{i}'].sign(body) for i in range(3)]}
    with pytest.raises(ProtocolError): env.c.check_receipt_certificate(s,proof)


def test_three_receipts_preclude_omitting_input_quorum_under_one_fault(env):
    _,all_subs=bundle(env); receipts(env,[all_subs[0]],env.guards[:3])
    omitted,subs=bundle(env,[0,1,1,1]); proof=receipts(env,subs)
    env.clock[0]+=100
    for g in env.guards[:3]:
        with pytest.raises(ProtocolError,match='omits or replaces'): g.prepare(omitted,proof)
    honest_vote=env.guards[3].prepare(omitted,proof)
    evil_vote=env.ids['A0'].sign(env.c.input_body(omitted))
    with pytest.raises(ProtocolError): env.c.certificate(env.c.input_body(omitted),[evil_vote,honest_vote])


def test_local_receipt_refuses_replacement_even_with_other_quorum_proof(env):
    m,subs=bundle(env); _,other=bundle(env,alter=1)
    env.guards[0].receive(other[0])
    proof=receipts(env,subs,env.guards[1:])
    with pytest.raises(ProtocolError,match='omits or replaces'): env.guards[0].prepare(m,proof)


def test_full_payload_can_be_recovered_from_receipting_peer_after_deadline(env):
    m,subs=bundle(env); proof=receipts(env,subs,env.guards[1:])
    env.clock[0]+=100
    fetched=[env.guards[1].fetch_submission(s['collection_hash'],s['client_id'])['submission'] for s in subs]
    rebuilt=env.c.manifest(env.ctx,env.parent,[p for s in fetched for p in s['inputs']],presence=[1]*4)
    assert rebuilt==m
    assert env.guards[0].prepare(rebuilt,proof)


def test_receipt_vs_close_are_exclusive_across_two_sqlite_connections(env):
    m,subs=bundle(env); _,conflict=bundle(env,alter=1)
    proof=receipts(env,subs,env.guards[1:]); barrier=Barrier(2)
    def action(kind):
        g=AggregatorGuard(env.c,env.ids['A0'],env.path/'A0.sqlite',env.initial,clock_ms=lambda:env.clock[0])
        try:
            barrier.wait(timeout=5)
            try:
                if kind=='receipt': g.receive(conflict[0])
                else: g.prepare(m,proof)
                return True
            except ProtocolError: return False
        finally: g.ledger.close()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(action,['receipt','close']))
    assert sum(results)==1
    collection=env.guards[0].ledger.collection(env.opened[0]['collection_hash'])
    stored=env.guards[0].fetch_submission(env.opened[0]['collection_hash'],'C0')
    if results[0]:
        assert stored['submission']==conflict[0] and collection['phase']=='open'
        assert env.guards[0].ledger.row(1) is None
    else:
        assert stored is None and collection['phase']=='closed'
        assert env.guards[0].ledger.row(1)['phase']=='prepared'


def test_receipts_and_closed_lock_survive_restart(env):
    m,subs=bundle(env); proof=receipts(env,subs)
    vote=env.guards[0].prepare(m,proof)
    recovered=AggregatorGuard(env.c,env.ids['A0'],env.path/'A0.sqlite',env.initial,clock_ms=lambda:env.clock[0])
    try:
        assert recovered.prepare(m,proof)==vote
        other,_=bundle(env,alter=1)
        with pytest.raises(ProtocolError): recovered.prepare(other,proof)
    finally: recovered.ledger.close()


def test_service_returns_public_receipt_and_payload_but_no_timestamp_override(env):
    owner=LocalAggregator.__new__(LocalAggregator); owner.guard=env.guards[0]
    owner.reader=SimpleNamespace(registration_checked=True)
    _,subs=bundle(env,[1,0,0,0]); s=subs[0]
    vote=owner.action('collect',{'submission':s})
    query={'collection_hash':s['collection_hash'],'client_id':'C0'}
    assert owner.action('receipt',query)==vote
    assert owner.action('submission',query)['submission']==s
    with pytest.raises(ProtocolError): owner.action('collect',{'submission':s,'now_ms':0})


def test_collection_context_cannot_change_parent_model_or_counter(env):
    with pytest.raises(ProtocolError): env.guards[0].open_collection(env.ctx,'00'*32)
    other=RoundContext(env.c.session_id,1,2,digest(env.initial),env.c.policy.policy_hash)
    with pytest.raises(ProtocolError): env.guards[0].open_collection(other,env.parent)


def test_empty_collection_cannot_close_early_but_can_close_at_deadline(env):
    m,_=bundle(env,[0]*4)
    with pytest.raises(ProtocolError): env.guards[0].prepare(m,[])
    env.clock[0]+=100
    assert env.guards[0].prepare(m,[])


def test_receipt_deadline_is_sampled_after_waiting_for_sqlite_lock(env):
    _,subs=bundle(env,[1,0,0,0]); ready=Event(); go=Event(); sampled=Event()
    def worker():
        def clock(): sampled.set(); return env.clock[0]
        g=AggregatorGuard(env.c,env.ids['A0'],env.path/'A0.sqlite',env.initial,clock_ms=clock)
        try:
            ready.set(); go.wait(timeout=5)
            try: g.receive(subs[0]); return True
            except ProtocolError: return False
        finally: g.ledger.close()
    with ThreadPoolExecutor(max_workers=1) as pool:
        task=pool.submit(worker)
        assert ready.wait(timeout=5)
        env.guards[0].ledger.db.execute('BEGIN IMMEDIATE')
        try:
            go.set()
            assert not sampled.wait(timeout=.05)
            env.clock[0]+=100
        finally: env.guards[0].ledger.db.execute('COMMIT')
        assert task.result(timeout=5) is False
    assert sampled.is_set()
    assert env.guards[0].fetch_submission(subs[0]['collection_hash'],'C0') is None


def test_receipt_proofs_cannot_be_swapped_between_clients(env):
    m,subs=bundle(env); proof=receipts(env,subs); proof[0],proof[1]=proof[1],proof[0]
    with pytest.raises(ProtocolError): env.guards[0].prepare(m,proof)
    assert env.guards[0].ledger.collection(env.opened[0]['collection_hash'])['phase']=='open'


def test_transport_receipt_does_not_apply_plaintext_boundary_filter(env):
    body=env.ctx.payload(env.c.policy,client_id='C0',key_handle=env.c.handles[0],values=[65535,20001,0])
    submission=env.c.submission(env.ctx,env.parent,'C0',[env.ids['C0'].sign(body)])
    assert env.guards[0].receive(submission)['body']['submission_hash']==digest(submission)


def test_receipts_cannot_precede_opening_and_v2_prepare_cannot_bypass_close(env):
    m,subs=bundle(env); proof=receipts(env,subs)
    unopened=AggregatorGuard(env.c,env.ids['A0'],env.path/'unopened.sqlite',env.initial,
                             create=True,clock_ms=lambda:env.clock[0])
    try:
        with pytest.raises(ProtocolError): unopened.receive(subs[0])
        with pytest.raises(ProtocolError): unopened.prepare(m,proof)
        assert unopened.ledger.row(1) is None
    finally: unopened.ledger.close()

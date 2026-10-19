"""Seeded-component privacy boundary, domain binding and compiler input layout."""
from copy import deepcopy
from functools import reduce
from operator import xor
import pytest
from trustlessfl.crypto import Identity, ProtocolError, digest
from trustlessfl.seed_mpc_prss import (MASK_MODE, held_components, seed_packet, open_seed_packet,
    component_words, combined_mask, private_round_words)
from trustlessfl.seed_mpc_client_app import provision


def fixture():
    identities={name:Identity.generate(name) for name in ['C0',*[f'A{i}' for i in range(4)]]}
    registration={'client_id':'C0','session_id':'session','committee_epoch':1,'key_handle':'handle',
                  'policy_hash':digest('policy'),'execution_hash':digest('execution')}
    return identities,registration,[bytes([i+1])*16 for i in range(4)]


def test_each_recipient_gets_exactly_three_seeds_and_two_recipients_cover_four():
    ids,reg,seeds=fixture(); registry={n:i.public() for n,i in ids.items()}
    observations=[]
    for p in range(4):
        packet=seed_packet(ids['C0'],seeds,reg,p,registry[f'A{p}'])
        actual=open_seed_packet(packet,ids[f'A{p}'],registry,reg,p)
        assert actual=={j:seeds[j] for j in held_components(p)}
        assert p not in actual
        observations.append(actual)
    assert set(observations[0])|set(observations[1])==set(range(4))


@pytest.mark.parametrize('fault',['recipient','ciphertext','session','client','handle','policy','execution','signature','component-order'])
def test_seed_packets_reject_replay_tamper_and_wrong_recipient(fault):
    ids,reg,seeds=fixture(); registry={n:i.public() for n,i in ids.items()}
    packet=seed_packet(ids['C0'],seeds,reg,0,registry['A0']); changed=deepcopy(reg); receiver=ids['A0']; party=0
    if fault=='recipient': receiver=ids['A1']; party=1
    elif fault=='ciphertext':
        body=deepcopy(packet['body']); body['encrypted']['ciphertext']='00'+body['encrypted']['ciphertext'][2:]
        packet=ids['C0'].sign(body)
    elif fault=='signature': packet['signature']='00'*64
    elif fault=='component-order':
        body=deepcopy(packet['body']); body['components'].reverse(); packet=ids['C0'].sign(body)
    else:
        key={'session':'session_id','client':'client_id','handle':'key_handle','policy':'policy_hash','execution':'execution_hash'}[fault]
        changed[key]='changed'
    with pytest.raises(ProtocolError): open_seed_packet(packet,receiver,registry,changed,party)


def test_mask_stitches_across_aes_and_chunk_boundaries_and_binds_round_registration_component():
    _,reg,seeds=fixture()
    full=combined_mask(seeds,reg,1,65)
    assert full==combined_mask(seeds,reg,1,31)+combined_mask(seeds,reg,1,34,offset=31)
    assert full!=combined_mask(seeds,reg,2,65)
    assert full!=combined_mask(seeds,{**reg,'session_id':'new-session'},1,65)
    assert component_words(seeds[0],reg,0,1,65)!=component_words(seeds[0],reg,1,1,65)
    streams=[component_words(seed,reg,j,1,65) for j,seed in enumerate(seeds)]
    assert full==tuple(reduce(xor,c) for c in zip(*streams))


def test_one_aggregator_observation_is_unchanged_when_its_missing_seed_changes():
    _,reg,seeds=fixture()
    for p in range(4):
        changed=list(seeds); changed[p]=bytes([99])*16
        assert {j:seeds[j] for j in held_components(p)}=={j:changed[j] for j in held_components(p)}
        assert combined_mask(seeds,reg,1,65)!=combined_mask(changed,reg,1,65)


def test_private_input_layout_matches_client_chunk_component_holder_order():
    _,reg,seeds=fixture(); dimension=65; chunk=32; padded=96
    for party in range(4):
        local={j:seeds[j] for j in held_components(party)}
        values=list(private_round_words([local],[reg],party,3,dimension,4))
        expected=[]
        streams={j:component_words(seeds[j],reg,j,3,padded) for j in local}
        for offset in range(0,padded,chunk):
            for j in range(4):
                if j!=party: expected+=streams[j][offset:offset+chunk]
        assert values==expected and len(values)==3*padded
    with pytest.raises(ProtocolError): list(private_round_words([dict(enumerate(seeds))],[reg],0,3,65,4))


def test_canonical_modular_restoration_at_signed_endpoints_and_wide_sum():
    _,reg,seeds=fixture(); q=65536
    update=(-20000,-1,0,1,20000,-32768,32767)
    masks=combined_mask(seeds,reg,1,len(update))
    wire=[(x+m)%q for x,m in zip(update,masks)]
    residue=[(y-m)%q for y,m in zip(wire,masks)]
    restored=[r-q if r>=q//2 else r for r in residue]
    assert restored==list(update)
    assert 4*restored[4]==80000 and (4*restored[4])%q!=80000


def test_client_provisioning_writes_four_seeds_and_only_recipient_encrypted_packets(tmp_path):
    import json
    ids,reg,_=fixture()
    prep={'mask_mode':MASK_MODE,'session_id':reg['session_id'],'policy_hash':reg['policy_hash'],
          'execution_hash':reg['execution_hash'],'installation':'/installation','snapshot_version':2,
          'aggregator_public':{n:i.public() for n,i in ids.items() if n.startswith('A')}}
    directory=tmp_path/'C0'; provision(directory,prep,0)
    private=json.loads((directory/'client.json').read_text())
    assert 'seed_key' not in private and len(private['component_seeds'])==4
    registration=json.loads((directory/'public-registration.json').read_text())
    registry={**{n:i.public() for n,i in ids.items()},'C0':registration['public']}
    for p in range(4):
        path=directory/f'component-packets/A{p}.json'
        packet=json.loads(path.read_text())
        held=open_seed_packet(packet,ids[f'A{p}'],registry,registration['envelope']['body'],p)
        assert set(held)==set(held_components(p)) and path.stat().st_mode & 0o777==0o600
        assert all(seed not in path.read_text() for seed in private['component_seeds'])


def test_local_prg_implementation_is_bound_to_execution():
    from trustlessfl.seed_mpc_prss import local_source_hashes, require_mask_implementation
    hashes=local_source_hashes()
    require_mask_implementation(hashes)
    for invalid in (None,{}, {**hashes,'seed_mpc_prss.py':'00'*32}):
        with pytest.raises(ProtocolError): require_mask_implementation(invalid)


@pytest.mark.parametrize('dimension',[0,-1,True,1.5])
def test_private_component_input_rejects_invalid_dimension(dimension):
    _,reg,seeds=fixture()
    with pytest.raises(ProtocolError):
        list(private_round_words([{j:seeds[j] for j in held_components(0)}],[reg],0,1,dimension,4))


def test_registration_input_checks_actual_decrypted_seed_replicas():
    from trustlessfl.seed_mpc_prss import registration_words
    _,reg,seeds=fixture()
    for party in range(4):
        local={j:seeds[j] for j in held_components(party)}
        words=list(registration_words([local],party))
        expected=[]
        for j in range(4):
            if j in local:
                value=int.from_bytes(seeds[j],'big')
                expected.extend([value & ((1<<64)-1),value>>64])
        assert words==expected and len(words)==6


@pytest.mark.parametrize('blocks',[1,4,8,16,32,64])
def test_private_component_layout_supports_packed_lanes_and_tail_padding(blocks):
    _,reg,seeds=fixture(); dimension=65; chunk=blocks*8
    padded=((dimension+chunk-1)//chunk)*chunk
    for party in range(4):
        local={j:seeds[j] for j in held_components(party)}
        actual=list(private_round_words([local],[reg],party,1,dimension,blocks))
        streams={j:component_words(seeds[j],reg,j,1,padded) for j in local}
        expected=[v for start in range(0,padded,chunk) for j in range(4) if j!=party
                  for v in streams[j][start:start+chunk]]
        assert actual==expected and len(actual)==3*padded

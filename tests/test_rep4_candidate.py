"""Bounds and adversarial transcript witnesses for the Rep4 candidate."""
from dataclasses import asdict, replace
import json
import random

import pytest

from trustlessfl.crypto import ProtocolError
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.rep4_external import reconstruct_replicated_triples
from experiments.run_seed_mpc_probe import build_fixture
from trustlessfl.crypto import digest


def messages_for(triples, k):
    rng = random.Random(11011)
    modulus = 1 << k
    bodies = [bytearray() for _ in range(4)]
    for triple in triples:
        for value in triple:
            components = [rng.randrange(modulus) for _ in range(3)]
            components.append((value-sum(components))%modulus)
            for p in range(4):
                for g in [(p+1)%4,(p+2)%4,(p+3)%4]:
                    bodies[p] += components[g].to_bytes(k//8,'little')
    return [bytes(body) for body in bodies]


@pytest.mark.parametrize('k',[64,128])
def test_full_replicated_triples_reconstruct_and_reject_each_corrupt_party(k):
    modulus = 1 << k
    triples = [[modulus-7,modulus-3,21],[1<< (k-1),3,1 << (k-1)]]
    bodies = messages_for(triples,k)
    assert reconstruct_replicated_triples(bodies,2,k) == triples
    for p in range(4):
        for offset in [0,k//8-1,len(bodies[p])-1]:
            changed = list(bodies)
            raw = bytearray(changed[p]); raw[offset] ^= 0x80
            changed[p] = bytes(raw)
            with pytest.raises(ProtocolError,match='inconsistent replicated'):
                reconstruct_replicated_triples(changed,2,k)


def test_consistent_but_invalid_triple_is_rejected():
    with pytest.raises(ProtocolError,match='invalid replicated input triple'):
        reconstruct_replicated_triples(messages_for([[7,9,62]],64),1,64)


def test_partial_or_extra_triple_frame_is_rejected():
    bodies = messages_for([[7,9,63]],64)
    for tail in [b'',b'\0\0']:
        wrong = list(bodies); wrong[2] = bodies[2][:-1]+tail
        with pytest.raises(ProtocolError,match='message length'):
            reconstruct_replicated_triples(wrong,1,64)


def test_ring_zero_divisor_breaks_single_field_style_checks():
    # Exhaustive toy ring demonstrates why a prime-field bound cannot be copied.
    modulus,delta = 256,128
    assert sum((rho*delta*(delta-1))%modulus==0 for rho in range(modulus)) == 128
    # A high-bit modification to an input triple's a passes c=a*b for even b.
    assert sum(((7+delta)*b)%modulus==(7*b)%modulus for b in range(modulus)) == 128


def test_capacity_covers_full_model_and_rejects_wrap_before_selection():
    policy = SeedMPCPolicy(61706,4,20000,2500000000)
    policy.validate_ring(64)
    assert policy.norm_capacity == 24682400000000
    with pytest.raises(ProtocolError): policy.validate_ring(32)
    oversized = replace(policy,word_bits=32,coordinate_cap=1000000000)
    with pytest.raises(ProtocolError): oversized.validate_ring(64)
    oversized.validate_ring(128)
    with pytest.raises(ProtocolError): replace(policy,squared_threshold=2**63).validate_ring(64)


@pytest.mark.parametrize('cap',[1,20000,32767])
def test_every_16bit_residue_matches_unique_signed_interval(cap):
    # Independent interval specification and signed binary interpretation.
    for residue in range(65536):
        permitted = residue <= cap or residue >= 65536-cap
        signed = int.from_bytes(residue.to_bytes(2,'big'),'big',signed=True)
        assert (-cap <= signed <= cap) == permitted
        if permitted:
            spec = residue if residue <= cap else residue-65536
            assert signed == spec


def test_global_norm_and_last_coordinate_adversarial_fixture():
    policy,_,_,expected,_=build_fixture('cross-chunk',65)
    # Both separate 15000 coordinates fit, but their combined norm exceeds T.
    assert 15000**2 < policy.squared_threshold < 2*15000**2
    first,second,last=expected
    assert first['count']==3 and first['sum'][0]==-20000 and first['sum'][-1]==20000
    assert second['count']==2 and second['sum'][0]==20000 and second['sum'][-1]==-20000
    assert last=={'status':'abort'}


def test_two_rep4_parties_can_reconstruct_shared_input():
    # Rep4 f=1 is essential: P0 and P1 together possess all four components.
    key=0x1234567890ABCDEF
    components=[11,23,47,(key-81)%(1<<64)]
    views=[{(p+j)%4:components[(p+j)%4] for j in (1,2,3)} for p in (0,1)]
    assert len(views[0])==3
    combined={**views[0],**views[1]}
    assert len(combined)==4 and sum(combined.values())%(1<<64)==key


@pytest.mark.parametrize('mutation',['manifest-threshold','manifest-dimension','manifest-cap','different-policy'])
def test_compile_reuse_rejects_modified_manifest_or_policy(tmp_path,monkeypatch,mutation):
    import experiments.run_seed_mpc_probe as runner
    root=tmp_path/'repo'; root.mkdir()
    (root/'trustlessfl').symlink_to(runner.ROOT/'trustlessfl',target_is_directory=True)
    (root/'experiments').mkdir()
    copied_script=root/'experiments/run_seed_mpc_probe.py'
    copied_script.symlink_to(runner.__file__)
    monkeypatch.setattr(runner,'__file__',str(copied_script))
    monkeypatch.setattr(runner,'ROOT',root)
    ports=iter([21000,22000])
    monkeypatch.setattr(runner,'free_port_base',lambda _:next(ports))
    install=tmp_path/'mp-spdz'; install.mkdir()
    (install/'rep4-ring-party.x').touch()
    cached=root/'.cache/seed-mpc/runs/cached'; cached.mkdir(parents=True)
    policy=SeedMPCPolicy(2,4,20000,400000000,scale=1)
    old={**asdict(policy),'clients':4,'parties':4,'backend':'rep4','ring_bits':64,
         'seed_encoding':'packed64','coordinate_circuit':'chunked','round_slots':3,
         'chunk_blocks':4,'output_mode':'native-public','rep4_input_mode':'replicated-triples-v1',
         'client_port':22000}
    if mutation=='different-policy': old['squared_threshold']=100
    record={'policy_hash':digest(old)}
    if mutation.startswith('manifest-'):
        field={'manifest-threshold':'squared_threshold','manifest-dimension':'dimension',
               'manifest-cap':'coordinate_cap'}[mutation]
        old[field]+=1
    (cached/'policy.json').write_text(json.dumps(old))
    (cached/'result.json').write_text(json.dumps(record))
    # Rejection happens before compiler, TLS setup, or native parties are started.
    with pytest.raises(ProtocolError,match='manifest|policy/shape'):
        runner.run_probe(install,backend='rep4',coordinate_circuit='chunked',compiled_workspace=cached)

import copy
import hashlib
import json
from pathlib import Path
import ssl
import threading
from http.server import BaseHTTPRequestHandler

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from trustlessfl import seed_mpc_distributed as d
from trustlessfl.crypto import ProtocolError, canonical, digest
from trustlessfl.seed_mpc_prss import open_seed_packet
from trustlessfl.seed_mpc_backend import native_command


@pytest.fixture
def session(tmp_path,monkeypatch):
    pin={'version':'0.4.3','archive_sha256':'official','source_manifest_hash':'trusted',
        'applied_patches':['rep4-holder-checked-native-import-v1'],'compile_flags':['-R','64','-Z','4','-M'],
        'native_security':'malicious; no caller-supplied flags','binary_sha256':'local-only'}
    monkeypatch.setattr(d,'pin_backend',lambda _:copy.deepcopy(pin))
    def compile_(workspace,*args):
        root=Path(workspace)/'Programs'
        for name in ('Bytecode/program.bc','Schedules/program.sch'):
            p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(b'checked-compiler-output')
        return {'compile_invocations':1}
    monkeypatch.setattr(d,'compile_circuit',compile_)
    installation=tmp_path/'installation'
    monkeypatch.setattr(d,'circuit_bytes',lambda _:b'trusted test AES fixture')
    monkeypatch.setattr(d,'CIRCUIT_SHA256',hashlib.sha256(b'trusted test AES fixture').hexdigest())
    source=tmp_path/'model.py'; source.write_text('import torch\ndef make_model(): return torch.nn.Linear(1,2)\n')
    config=tmp_path/'model.json'; config.write_bytes(canonical({'plugin':'model.py',
        'policy':{'coordinate_cap':20000,'squared_threshold':400000000,'scale':10000,'minimum_accepted':2}}))
    peers=[tmp_path/f'A{i}' for i in range(4)]
    for i,p in enumerate(peers): d.init_aggregator(p,i,f'a{i}.example.test')
    bundle=tmp_path/'bundle'; result=d.plan(bundle,installation,config,[p/'public.json' for p in peers],clients=2)
    expected=result['contract_hash']
    for p in peers: d.approve(p,bundle,expected,installation)
    import numpy as np
    train=tmp_path/'train.npz'; np.savez(train,x=np.ones((2,1),dtype=np.float32),y=np.zeros(2,dtype=np.int64))
    clients=[tmp_path/f'C{i}' for i in range(2)]
    for i,p in enumerate(clients): d.provision_client(p,bundle,expected,i,train,installation,source)
    final=d.finalize(bundle,expected,[p/'approval.json' for p in peers],[p/'enrollment.json' for p in clients])
    return {'root':tmp_path,'peers':peers,'clients':clients,'bundle':bundle,'expected':expected,
        'deployment':final['public_deployment_hash'],'installation':installation,'pin':pin}


def test_independent_key_and_public_bundle(session):
    s=session; public=(s['bundle']/'deployment-public.json').read_text()
    assert 'PRIVATE KEY' not in public and 'component_seeds' not in public
    from trustlessfl.crypto import Identity
    private=d.read(s['clients'][0]/'client.json')
    registration=d.read(s['clients'][0]/'public-registration.json')['envelope']['body']
    for slot,peer in enumerate(s['peers']):
        identity=Identity.from_private(d.read(peer/'identity.json'))
        packet=d.read(s['clients'][0]/f'component-packets/A{slot}.json')
        seeds=open_seed_packet(packet,identity,d.read(s['bundle']/'deployment-public.json')['committee']['registry'],registration,slot)
        assert len(seeds)==3 and slot not in seeds
        assert private['component_seeds'][slot] not in canonical(packet).decode()
    assert len({d.read(p/'identity.json')['signing'] for p in s['peers']})==4


def test_contract_requires_exact_authenticated_fingerprint(session):
    with pytest.raises(ProtocolError,match='fingerprint'): d.check_plan(session['bundle'],'0'*64)


@pytest.mark.parametrize('filename', ['model.py','mpc/policy.json','mpc/Programs/Bytecode/program.bc',
    'mpc/Programs/Source/seed_mpc_chunked_session.mpc'])
def test_mutated_public_artifact_rejected(session,filename):
    p=session['bundle']/filename
    if filename=='mpc/policy.json':
        value=d.read(p); value['coordinate_cap']+=1; p.write_bytes(canonical(value))
    else: p.write_bytes(p.read_bytes()+b' ')
    with pytest.raises(ProtocolError): d.check_plan(session['bundle'],session['expected'])


def test_self_consistent_bytecode_requires_independent_compile(session):
    s=session; b=d.read(s['bundle']/'plan.json')
    p=s['bundle']/'mpc/Programs/Bytecode/program.bc'; p.write_bytes(b'malicious bytecode')
    b['artifacts']=d.artifacts(s['bundle']/'mpc'); (s['bundle']/'plan.json').write_bytes(canonical(b))
    with pytest.raises(ProtocolError,match='independent circuit'):
        d.approve(s['peers'][0],s['bundle'],digest(b),s['installation'])


def test_backend_semantics_allow_local_binary_changes(session,monkeypatch):
    s=session; altered={**s['pin'],'binary_sha256':'another-approved-host-build'}
    assert d.backend_contract(altered)==d.backend_contract(s['pin'])
    altered['source_manifest_hash']='unapproved protocol'
    assert d.backend_contract(altered)!=d.backend_contract(s['pin'])


def test_missing_operator_approval_rejected(session):
    s=session
    with pytest.raises(ProtocolError,match='incomplete'):
        d.finalize(s['bundle'],s['expected'],[p/'approval.json' for p in s['peers'][:3]],[p/'enrollment.json' for p in s['clients']])


def test_client_certificate_substitution_rejected(session):
    s=session; path=s['clients'][0]/'enrollment.json'; b=d.read(path)
    b['body']['certificate']=d.read(s['clients'][1]/'enrollment.json')['body']['certificate']
    path.write_bytes(canonical(b))
    with pytest.raises(ProtocolError):
        d.finalize(s['bundle'],s['expected'],[p/'approval.json' for p in s['peers']],[p/'enrollment.json' for p in s['clients']])


def test_role_bind_ignores_unlisted_files_and_pins_local_inputs(session):
    s=session; secret=s['bundle']/'private-accident.key'; secret.write_text('NEVER TRANSFER')
    directory=s['clients'][0]
    d.bind(directory,s['bundle'],s['expected'],expected_deployment=s['deployment'])
    assert not (directory/'public/private-accident.key').exists()
    assert d.check_client_role(directory/'role.json')['slot']==0
    config=d.read(directory/'registration-config.json')
    assert config['party_hosts']==[f'a{i}.example.test' for i in range(4)]
    assert list((directory/'Player-Data').glob('*.key'))==[directory/'Player-Data/C0.key']


def test_changed_enrollment_hash_rejected(session):
    s=session
    with pytest.raises(ProtocolError,match='fingerprint'):
        d.bind(s['clients'][0],s['bundle'],s['expected'],expected_deployment='0'*64)


def test_peer_must_not_have_certificate_issuing_authority(session):
    for peer in session['peers']:
        pem=d.read(peer/'public.json')['body']['certificate']
        cert=x509.load_pem_x509_certificate(pem.encode())
        assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        assert not cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign


def test_network_native_command_cannot_weaken_security(tmp_path):
    argv=native_command(tmp_path/'rep4-ring-party.x',15000,2,'program',ip_file=tmp_path/'party-hosts.txt')
    assert '-ip' in argv and '-h' not in argv
    assert '--semi-honest' not in argv and '-u' not in argv


@pytest.mark.parametrize('host',['a0:1','http://a0','a0\n127.0.0.1','../a0',''])
def test_host_injection_rejected(host):
    with pytest.raises(ProtocolError): d.safe_host(host)


def test_rpc_unapproved_or_plain_endpoint_fails_before_network():
    with pytest.raises(ProtocolError):
        d.remote_rpc('http://a0:17000','head',None,timeout=1,meter=None,transport={'peers':{}})


@pytest.mark.parametrize('field',['training','rounds','initial_model','services'])
def test_final_enrollment_cannot_change_approved_plan(session,field):
    s=session; directory=s['clients'][0]
    d.bind(directory,s['bundle'],s['expected'],expected_deployment=s['deployment'])
    deployment=d.read(directory/'deployment.json')
    public_path=Path(deployment['public_bundle'])/'deployment-public.json'; public=d.read(public_path)
    public[field]={'changed':True}
    public_path.write_bytes(canonical(public)); deployment[field]=public[field]
    deployment['public_deployment_hash']=digest(public)
    with pytest.raises(ProtocolError,match='approved plan'): d.validate_local_deployment(deployment)


def test_actual_mtls_and_authorization(tmp_path):
    for slot in range(2):
        d.certificate(tmp_path,f'P{slot}','127.0.0.1')
    roots=tmp_path/'roots.pem'
    roots.write_text(''.join((tmp_path/f'P{i}.pem').read_text() for i in range(2)))
    expected=d.cert_fingerprint((tmp_path/'P0.pem').read_text())
    transport={'certificate':str(tmp_path/'P0.pem'),'key':str(tmp_path/'P0.key'),'roots':str(roots),
        'coordinator_fingerprint':expected}
    deployment={'rpc_transport':transport}
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            allowed=d.authorize_rpc_peer(self.connection,deployment)
            self.rfile.read(int(self.headers.get('Content-Length',0)))
            raw=canonical({'result':{'authenticated':True}})
            self.send_response(200 if allowed else 403); self.send_header('Content-Length',str(len(raw))); self.end_headers()
            self.wfile.write(raw)
        def log_message(self,*_): pass
    server=d.DistributedHTTPServer(('127.0.0.1',0),Handler,d.server_tls(deployment,0))
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    url=f'https://127.0.0.1:{server.server_address[1]}'
    transport['peers']={url:expected}
    try:
        assert d.remote_rpc(url,'head',{},timeout=2,meter=None,transport=transport)=={'authenticated':True}
        wrong_role={**transport,'certificate':str(tmp_path/'P1.pem'),'key':str(tmp_path/'P1.key')}
        with pytest.raises(ProtocolError,match='rejected'):
            d.remote_rpc(url,'head',{},timeout=2,meter=None,transport=wrong_role)
        wrong_peer={**transport,'peers':{url:'0'*64}}
        with pytest.raises(ProtocolError,match='fingerprint'):
            d.remote_rpc(url,'head',{},timeout=2,meter=None,transport=wrong_peer)
        context=ssl.create_default_context(cafile=str(roots))
        import http.client
        connection=http.client.HTTPSConnection('127.0.0.1',server.server_address[1],context=context,timeout=2)
        with pytest.raises((ssl.SSLError,OSError)):
            connection.request('POST','/head',body=b'{}'); connection.getresponse()
        connection.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)

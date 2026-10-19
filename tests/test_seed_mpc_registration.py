import socket
import ssl
import struct
import subprocess
import threading

import pytest

from trustlessfl.crypto import ProtocolError
from trustlessfl import seed_mpc_registration as r
from trustlessfl.seed_mpc_committee import digest_words


def config(port=16000):
    return {'mask_mode':r.MASK_MODE,'parties':4,'clients':2,'ring_bits':64,
            'domain_modulus':1<<64,'output_mode':'native-public',
            'party_hosts':['127.0.0.1']*4,'client_port':port}


def test_frames_handle_fragmentation_and_eof():
    a,b=socket.socketpair()
    try:
        payload=struct.pack('<I',12)+b'a'*12
        def send():
            for value in payload: a.sendall(bytes([value]))
            a.close()
        thread=threading.Thread(target=send);thread.start()
        assert r.receive_frame(b)==b'a'*12
        with pytest.raises(ProtocolError,match='closed'): r.receive_exact(b,1)
        thread.join()
    finally: a.close();b.close()


def test_oversized_frame_rejected_without_reading_body():
    a,b=socket.socketpair()
    try:
        a.sendall(struct.pack('<I',100000))
        with pytest.raises(ProtocolError,match='oversized'): r.receive_frame(b)
    finally: a.close();b.close()


@pytest.mark.parametrize('field,value',[('ring_bits',32),('domain_modulus',65536),('parties',3),
    ('mask_mode','secret-aes-v1'),('output_mode','private'),('party_hosts',['a0']),('client_port',65535)])
def test_unsupported_protocol_rejected_before_network(field,value):
    c=config();c[field]=value
    with pytest.raises(ProtocolError): r.validate_config(c,0,'ab'*32)


@pytest.mark.parametrize('slot,tag',[(True,'ab'*32),(2,'ab'*32),(0,'x'*64),(0,'ab'*31)])
def test_bad_registration_identity_or_digest(slot,tag):
    with pytest.raises(ProtocolError): r.validate_config(config(),slot,tag)


@pytest.mark.parametrize('mode',['normal','different-spec','wrong-ring','wrong-party-certificate'])
def test_four_party_real_mtls_registration(tmp_path,mode):
    from trustlessfl.seed_mpc_distributed import certificate
    for name in ['C0',*(f'P{i}' for i in range(4))]: certificate(tmp_path,name,'127.0.0.1')
    subprocess.run(['openssl','rehash',str(tmp_path)],check=True,capture_output=True)
    listeners=[]
    for base in range(21000,30000,8):
        try:
            for i in range(4):
                sock=socket.socket();sock.bind(('127.0.0.1',base+i));sock.listen();sock.settimeout(5);listeners.append(sock)
            break
        except OSError:
            for sock in listeners: sock.close()
            listeners=[]
    assert len(listeners)==4
    frames={}; failures=[]
    def serve(party):
        conn=None
        try:
            plain,_=listeners[party].accept();plain.settimeout(5)
            assert r.receive_frame(plain)==b'0'
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            cert_party=0 if mode=='wrong-party-certificate' and party==1 else party
            context.load_cert_chain(tmp_path/f'P{cert_party}.pem',tmp_path/f'P{cert_party}.key')
            context.load_verify_locations(cafile=str(tmp_path/'C0.pem'));context.verify_mode=ssl.CERT_REQUIRED
            conn=context.wrap_socket(plain,server_side=True)
            spec=struct.pack('<iii',ord('R'),32 if mode=='wrong-ring' else 64,64)
            if mode=='different-spec' and party==3: spec=struct.pack('<iii',ord('R'),64,32)
            raw=struct.pack('<I',len(spec))+spec
            for byte in raw: conn.sendall(bytes([byte]))
            frames[party]=r.receive_frame(conn)
        except (OSError,ProtocolError) as exc: failures.append(type(exc).__name__)
        finally:
            if conn:conn.close()
    threads=[threading.Thread(target=serve,args=(i,),daemon=True) for i in range(4)]
    for t in threads:t.start()
    try:
        if mode=='normal':
            counters=r.register(config(base),0,'ab'*32,directory=tmp_path,timeout=2)
            expected=b''.join(struct.pack('<Q',w%(1<<64)) for w in digest_words('ab'*32))
        else:
            with pytest.raises((ProtocolError,ssl.SSLError)):
                r.register(config(base),0,'ab'*32,directory=tmp_path,timeout=2)
    finally:
        for t in threads:t.join(timeout=6)
        for s in listeners:s.close()
    if mode=='normal':
        assert not failures
        assert frames=={i:expected for i in range(4)}
        assert counters['seed_registration']['sent_bytes']==4*36


def test_distributed_client_needs_no_backend(session,monkeypatch):
    # Fixture comes from test_seed_mpc_distributed when imported below.
    from trustlessfl import seed_mpc_distributed as d
    def forbidden(*_): raise AssertionError('client must not pin or execute a native backend')
    monkeypatch.setattr(d,'pin_backend',forbidden)
    directory=session['root']/'C-new'
    d.provision_client(directory,session['bundle'],session['expected'],0,
        session['root']/'train.npz',None,session['root']/'model.py')
    assert d.read(directory/'client.json')['registration_transport']==r.TRANSPORT
    directory=session['clients'][0]
    d.bind(directory,session['bundle'],session['expected'],expected_deployment=session['deployment'])
    private=d.read(directory/'client.json'); deployment=d.read(directory/'deployment.json')
    assert private['installation'] is None
    assert private['registration_transport']==r.TRANSPORT
    assert deployment['native_binary'] is None and deployment['backend_pin'] is None


from test_seed_mpc_distributed import session

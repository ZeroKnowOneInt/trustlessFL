"""Packaged public circuit sources and local TLS provisioning; no experiment imports."""
from datetime import datetime, timedelta, timezone
import hashlib
from importlib.resources import files
from pathlib import Path
import os
import secrets
import socket
import subprocess
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from .crypto import ProtocolError

CIRCUIT_SHA256 = '40423a0cdaf5d4d34aba872c12660f115dc25c12eea6e24a9304578e79df6d04'
CIRCUIT_URL = 'https://raw.githubusercontent.com/mkskeller/bristol-fashion/1603ed6aa12348c2ef15ed8395b9b96e4c558b7f/aes_128.txt'

def write_private(path,body):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(body)


def ephemeral_range():
    try:
        low,high=map(int,Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split())
        return low,high
    except (OSError,ValueError):
        return 32768,60999


def free_port_base(parties):
    ephemeral_low,ephemeral_high=ephemeral_range()
    for _ in range(100):
        base=10000+secrets.randbelow(20000)
        if base<=ephemeral_high and base+parties+2>=ephemeral_low:
            continue
        opened=[]
        try:
            for port in range(base,base+parties+3):
                sock=socket.socket(); sock.bind(('0.0.0.0',port)); opened.append(sock)
            return base
        except OSError:
            pass
        finally:
            for sock in opened:sock.close()
    raise ProtocolError('no free local MPC port range')


def configure_tls(workspace,parties,clients):
    names=[f'P{i}' for i in range(parties)]+[f'C{i}' for i in range(clients)]
    certificates={}; private={}
    for name in names:
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
        now=datetime.now(timezone.utc)
        certificate=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]),critical=False)
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
            .sign(key,hashes.SHA256()))
        certificates[name]=certificate.public_bytes(serialization.Encoding.PEM)
        private[name]=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
    directories={}
    for name in names:
        actor=workspace/name
        actor.mkdir(mode=0o700)
        data=actor/'Player-Data'; data.mkdir(mode=0o700)
        for public_name,body in certificates.items():
            (data/f'{public_name}.pem').write_bytes(body)
        write_private(data/f'{name}.key',private[name])
        subprocess.run(['openssl','rehash',str(data)],check=True,stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        (actor/'Programs').symlink_to(workspace/'Programs',target_is_directory=True)
        directories[name]=actor
    return directories


def circuit_bytes(installation):
    source = installation/'Programs/Circuits/aes_128.txt'
    data = source.read_bytes() if source.exists() else urllib.request.urlopen(CIRCUIT_URL, timeout=30).read()
    if hashlib.sha256(data).hexdigest() != CIRCUIT_SHA256:
        raise ProtocolError('AES circuit hash differs from pinned artifact')
    return data



def stage_circuit_sources(workspace):
    source = Path(workspace)/'Programs/Source'
    source.mkdir(parents=True)
    result = {}
    for resource, target in (
        ('seed_mpc_chunked_session.py', 'seed_mpc_chunked_session.mpc'),
        ('seed_mpc_candidate_primitives.py', 'seed_mpc_candidate_primitives.py'),
        ('seed_mpc_primitives.py', 'seed_mpc_primitives.py'),
    ):
        raw = files('trustlessfl.mpc_sources').joinpath(resource).read_bytes()
        (source/target).write_bytes(raw)
        result[target] = hashlib.sha256(raw).hexdigest()
    return result

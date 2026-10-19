"""Local four-party MASCOT / external-input protocol validation, NOT Flower yet.

Fresh per-actor TLS directories are created for each fixture. Plaintext fixture
inputs belong to the trusted test harness; no private values go to MPC party
input files or into the public result. No fake/offline preprocessing is used.
"""
import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError, digest
from trustlessfl.private_bound import NoWrapPolicy

BACKEND_PRIMES=(2**127-1,2**255-19)
ROOT=Path(__file__).resolve().parents[1]


def write_private(path,body):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(body)


def free_port_base(parties):
    for _ in range(100):
        base=20000+secrets.randbelow(15000)
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


def backend_prime_for(length):
    if type(length) is not int or length < 1:
        raise ProtocolError('invalid application bit width')
    prime=next((value for value in BACKEND_PRIMES if length+40+2<=value.bit_length()),None)
    if prime is None:
        raise ProtocolError('application width exceeds MPC field security envelope')
    return prime


def run_fixture(installation,case='wrap',timeout=600,*,real_moduli=False,mask_max=15):
    installation=Path(installation).resolve()
    if not (installation/'mascot-party.x').is_file():
        raise ProtocolError('MASCOT binary missing; prepare the pinned MP-SPDZ distribution first')
    workspace=ROOT/'.cache/private-bound-mpc/runs'/uuid.uuid4().hex
    workspace.mkdir(parents=True,mode=0o700)
    parts=4; clients=4
    T=8 if case in ('wrap','negative-wrap') else 4
    policy=NoWrapPolicy(2,clients,2,1,5,mask_max,T,2)
    modulus=14760426300877770769 if real_moduli else 101
    hprf=OriginalAionHPRF(1,2,modulus,5*modulus,[[1,2]])
    port=free_port_base(parts); client_port=free_port_base(parts)
    while abs(port-client_port)<parts+4:client_port=free_port_base(parts)
    context=dict(task=uuid.uuid4().hex,epoch=1,round=1,threshold_mode="static",model_hash=digest([0,0]),
                 policy=asdict(policy),hprf_setup=hprf.public_setup(),parties=parts,faults=1)
    seed=int(digest(context),16)
    widths=policy.widths()
    lengths=[max(widths.values())+2,(3*hprf.q).bit_length()+2,
             (2*policy.mask_max*(hprf.p-1)+hprf.p).bit_length()+2]
    if hprf.q!=5*hprf.p or hprf.p%2==0:
        lengths.append((hprf.q*hprf.p+hprf.q//2).bit_length()+2)
    length=max(lengths)
    backend_prime=backend_prime_for(length)
    config=dict(threshold_mode="static",dimension=policy.dimension,clients=clients,parties=parts,coordinate_cap=policy.coordinate_cap,
                scale=policy.scale,spacing=policy.spacing,mask_max=policy.mask_max,squared_bound=policy.squared_bound,
                minimum_accepted=policy.minimum_accepted,client_port=client_port,seed=seed,
                backend_prime=backend_prime,context=context,
                hprf=dict(p=hprf.p,q=hprf.q,m=hprf.m,columns=list(hprf.column_sums),setup=hprf.public_setup()))
    config_path=workspace/'policy.json'
    config_path.write_text(json.dumps(config),encoding='utf-8')
    source=ROOT/'mpc/Programs/Source/aion_private_bound.mpc'
    copied=workspace/'Programs/Source/aion_private_bound.mpc'
    copied.parent.mkdir(parents=True); copied.write_bytes(source.read_bytes())
    compile_command=[sys.executable,str(installation/'compile.py'),'-P',str(backend_prime),
                     '-F',str(length),'-M','aion_private_bound','policy.json']
    with (workspace/'compile.log').open('w') as log:
        subprocess.run(compile_command,cwd=workspace,stdout=log,stderr=subprocess.STDOUT,
                       check=True,timeout=timeout)
    program='aion_private_bound-policy.json'
    actors=configure_tls(workspace,parts,clients)
    if case=='wrap':
        updates=[[2,2],[2,2],[2,2],[0,0]]; expected=dict(status='ok',count=4,sum=[6,6])
    elif case=='insufficient':
        updates=[[1,0],[2,2],[2,2],[2,2]]; expected=dict(status='abort')
    elif case=='negative-wrap':
        updates=[[-2,-2],[-2,-2],[-2,-2],[0,0]]; expected=dict(status='ok',count=4,sum=[-6,-6])
    else:
        updates=[[2,0],[-2,0],[1,1],[2,2]]; expected=dict(status='ok',count=3,sum=[1,1])
    mutations=[None]*clients
    if case=='off-grid':mutations[2]='off-grid'; expected=dict(status='ok',count=2,sum=[0,0])
    elif case=='coordinate-large':mutations[2]='coordinate-large'; expected=dict(status='ok',count=2,sum=[0,0])
    elif case=='nonboolean':mutations[2]='nonboolean'; expected=None
    elif case not in ('wrap','negative-wrap','norm','insufficient'):raise ProtocolError('unknown local fixture')
    processes=[]; handles=[]
    try:
        for i in range(parts):
            actor=actors[f'P{i}']; log=(actor/'native.log').open('w'); handles.append(log)
            args=[str(installation/'mascot-party.x'),'-e','-N',str(parts),'-pn',str(port),
                  '-h','127.0.0.1','-P',str(backend_prime),'-p',str(i),program]
            processes.append(subprocess.Popen(args,cwd=actor,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
        for i,update in enumerate(updates):
            actor=actors[f'C{i}']
            private=actor/'input.json'
            write_private(private,json.dumps(dict(client_id=i,key=secrets.randbelow(hprf.q),
                                                  update=update,mutation=mutations[i])).encode())
            log=(actor/'client.log').open('w'); handles.append(log)
            env=dict(os.environ,PYTHONPATH=str(ROOT),OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
            args=[sys.executable,'-m','trustlessfl.mpc_external_client','--mp-spdz-dir',str(installation),
                  '--private-input',str(private),'--config',str(config_path),'--output',str(actor/'pending-output.json')]
            processes.append(subprocess.Popen(args,cwd=actor,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
        started=time.monotonic(); early_failure=False
        while any(p.poll() is None for p in processes):
            if any(p.poll() not in (None,0) for p in processes):early_failure=True; break
            if time.monotonic()-started>timeout:
                raise TimeoutError('local MPC deadline exceeded')
            time.sleep(0.1)
        early_failure=early_failure or any(p.poll() not in (None,0) for p in processes)
        if early_failure:
            # Public protocol rejection may kill peers blocked on the aborting process.
            for p in processes:
                if p.poll() is None:os.killpg(p.pid,signal.SIGTERM)
            for p in processes:p.wait(timeout=10)
            if case!='nonboolean':
                raise ProtocolError('native MPC fixture failed; inspect actor-local logs')
            logs='\n'.join((actors[f'P{i}']/'native.log').read_text() for i in range(parts))
            if 'invalid canonical private input' not in logs:
                raise ProtocolError('nonboolean input failed for an unrelated reason')
            if any((actors[f'C{i}']/'pending-output.json').exists() for i in range(clients)):
                raise ProtocolError('rejected input produced a premature output')
            output={'status':'input-abort'}
        else:
            # Never accept an output before EVERY native party has completed MAC checks.
            if any(p.returncode!=0 for p in processes):raise ProtocolError('MPC completion failed')
            received=[json.loads((actors[f'C{i}']/'pending-output.json').read_text()) for i in range(clients)]
            if any(item!=received[0] for item in received):raise ProtocolError('authenticated output disagreement')
            output=received[0]
            if output!=expected:raise ProtocolError('MPC result differs from declared fixture result')
        result=dict(case=case,runtime='MP-SPDZ 0.4.3 MASCOT active preprocessing + authenticated external input/output',
                    parties=parts,committee_fault_budget=1,malicious_party_faults_injected=0,
                    malicious_client_input_injected=case in ('off-grid','coordinate-large','nonboolean'),
                    clients=clients,output=output,expected=expected,
                    elapsed_seconds=round(time.monotonic()-started,3),policy_hash=digest(config),
                    source_sha256=hashlib.sha256(copied.read_bytes()).hexdigest(),application_bit_length=length,
                    mask_max=policy.mask_max,statistical_security=40,field_bits=backend_prime.bit_length(),input_bitcheck_soundness_error=f'1/{backend_prime}',
                    real_author_moduli=real_moduli,public_matrix='controlled [1,2]; not author artifact matrix',
                    validation='local process protocol test; not official Flower or production security certification',passed=True)
        native_log=(actors['P0']/'native.log').read_text()
        traffic=re.search(r'Global data sent = ([0-9.]+) MB',native_log)
        result['global_data_sent_mb']=float(traffic.group(1)) if traffic else None
        (workspace/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        result['workspace']=str(workspace)
        return result
    finally:
        for process in processes:
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
        for process in processes:
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL); process.wait()
        for handle in handles:handle.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mp-spdz-dir',type=Path,required=True)
    parser.add_argument('--case',choices=('wrap','negative-wrap','norm','off-grid','coordinate-large','nonboolean','insufficient'),default='wrap')
    parser.add_argument('--timeout',type=int,default=600)
    parser.add_argument('--real-moduli',action='store_true')
    parser.add_argument('--mask-max',type=int,default=15)
    args=parser.parse_args()
    print(json.dumps(run_fixture(args.mp_spdz_dir,args.case,args.timeout,real_moduli=args.real_moduli,mask_max=args.mask_max),indent=2))


if __name__=='__main__':main()

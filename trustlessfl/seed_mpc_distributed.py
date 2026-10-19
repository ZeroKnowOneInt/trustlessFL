"""Independent operator provisioning and authenticated network Seed-MPC execution.

Contract fingerprints must be checked through an authenticated operator channel.
Public artifacts never grant local executable or toolchain approval.
"""
import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
import tomli_w

from .crypto import Identity, ProtocolError, canonical, digest, verify
from .seed_mpc_assets import stage_circuit_sources, circuit_bytes, CIRCUIT_SHA256, write_private
from .seed_mpc_backend import pin_backend
from .seed_mpc_compile import compile_circuit, artifacts
from .seed_mpc_model import make, flatten, model_contract, source_sha
from .seed_mpc_policy import SeedMPCPolicy
from .seed_mpc_prss import MASK_MODE, local_source_hashes

PROTOCOL = 'seed-mpc-distributed-v1'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, body, *, private=False):
    path=Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    raw=canonical(body)
    if private: write_private(path,raw)
    else:
        with path.open('xb') as stream: stream.write(raw)


def safe_host(host):
    if not isinstance(host,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',host):
        raise ProtocolError('only explicit IPv4 or DNS hosts supported')
    return host


def certificate(directory, name, host):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    names=[x509.DNSName(name),x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
    try: names.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError: names.append(x509.DNSName(host))
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(names),critical=False)
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,
            data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,
            encipher_only=None,decipher_only=None),critical=True)
        .sign(key,hashes.SHA256()))
    raw=cert.public_bytes(serialization.Encoding.PEM)
    (directory/f'{name}.pem').write_bytes(raw)
    write_private(directory/f'{name}.key',key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return raw.decode()


def checked_certificate(pem,name):
    cert=x509.load_pem_x509_certificate(pem.encode())
    if (cert.subject!=cert.issuer or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
            or cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value!=name):
        raise ProtocolError('self-signed non-CA role certificate required')
    cert.public_key().verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),cert.signature_hash_algorithm)
    names=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    if name not in names or any(re.fullmatch(r'[PC][0-9]+',value) and value!=name for value in names):
        raise ProtocolError('certificate claims another protocol role')
    if cert.not_valid_before_utc>datetime.now(timezone.utc) or cert.not_valid_after_utc<datetime.now(timezone.utc):
        raise ProtocolError('role certificate expired or not yet valid')
    return cert


def backend_contract(pin):
    if 'rep4-holder-checked-native-import-v1' not in pin['applied_patches']:
        raise ProtocolError('distributed execution requires approved active direct Rep4 backend')
    return {k:pin[k] for k in ('version','archive_sha256','source_manifest_hash','applied_patches','compile_flags','native_security')}


def init_aggregator(directory,slot,host):
    if type(slot) is not int or slot not in range(4): raise ProtocolError('invalid aggregator slot')
    safe_host(host); directory=Path(directory).resolve(); directory.mkdir(parents=True,exist_ok=False,mode=0o700)
    identity=Identity.generate(f'A{slot}')
    pem=certificate(directory,f'P{slot}',host)
    write(directory/'identity.json',identity.private(),private=True)
    body={'protocol':PROTOCOL,'kind':'aggregator-enrollment','slot':slot,'host':host,
          'public':identity.public(),'certificate':pem}
    write(directory/'public.json',{'body':body,'proof':identity.sign(body)})
    return {'role':identity.name,'public_file':str(directory/'public.json')}


def checked_enrollment(item,slot):
    body=item['body']; name=f'A{slot}'
    if body.get('protocol')!=PROTOCOL or body.get('kind')!='aggregator-enrollment' or body.get('slot')!=slot:
        raise ProtocolError('aggregator enrollment slot differs')
    safe_host(body['host'])
    if verify(item['proof'],{name:body['public']},sender=name)!=body:
        raise ProtocolError('invalid aggregator enrollment proof')
    cert=checked_certificate(body['certificate'],f'P{slot}')
    if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value!=f'P{slot}':
        raise ProtocolError('native certificate party differs')
    return body


def public_training(supplied):
    result={'epochs':1,'batch_size':64,'learning_rate':.05,'momentum':0.0,'weight_decay':0.0}
    if not isinstance(supplied,dict) or set(supplied)-set(result): raise ProtocolError('unsupported training settings')
    result.update(supplied)
    if any(type(result[k]) is not int or result[k]<1 for k in ('epochs','batch_size')):
        raise ProtocolError('invalid training size')
    for k in ('learning_rate','momentum','weight_decay'):
        v=result[k]
        if type(v) not in (int,float) or not math.isfinite(v) or v<0 or k=='learning_rate' and v==0:
            raise ProtocolError('invalid training option')
    return result


def plan(output,installation,model_config,peer_files,*,clients,rounds=2,seed=42,timeout=300,
         collection_window_ms=30000,party_port=15000,client_port=16000,rpc_port=17000,fleet_port=18000):
    """Public plan contains no train/test data or client private bootstrap."""
    if (type(clients) is not int or not 2<=clients<=1024 or type(rounds) is not int or not 1<=rounds<=20
            or type(seed) is not int or seed<0 or type(timeout) is not int or not 180<=timeout<=3600
            or type(collection_window_ms) is not int or not 1<=collection_window_ms<=3600000):
        raise ProtocolError('invalid distributed session size')
    ports=[party_port,client_port,rpc_port,fleet_port]
    if any(type(p) is not int or not 1024<=p<=30000 for p in ports) or any(abs(a-b)<8 for i,a in enumerate(ports) for b in ports[i+1:]):
        raise ProtocolError('distinct fixed network port ranges required')
    peers=[checked_enrollment(read(path),i) for i,path in enumerate(peer_files)]
    if len(peers)!=4 or len({p['host'] for p in peers})!=4: raise ProtocolError('four distinct operator hosts required')
    cfg=read(model_config)
    if set(cfg)-{'plugin','kwargs','training','policy'} or not {'plugin','policy'}<=set(cfg):
        raise ProtocolError('distributed model config must contain only public model/training/policy')
    source=(Path(model_config).resolve().parent/cfg['plugin']).resolve()
    spec={'plugin':str(source),'plugin_sha256':sha(source),'kwargs':cfg.get('kwargs',{}),'seed':seed,
          'adapter_sha256':source_sha(Path(__file__).with_name('seed_mpc_model.py'))}
    _,model,schema=make(spec); spec.update(schema=schema,schema_hash=digest(schema)); initial=flatten(model,schema).tolist()
    supplied=cfg['policy']
    if not isinstance(supplied,dict) or set(supplied)-set(SeedMPCPolicy.__dataclass_fields__) or not {'coordinate_cap','squared_threshold','scale'}<=set(supplied):
        raise ProtocolError('explicit static policy required')
    policy=SeedMPCPolicy(**{'dimension':schema['dimension'],'max_clients':clients,**supplied})
    if policy.dimension!=schema['dimension'] or policy.max_clients!=clients or policy.word_bits!=16:
        raise ProtocolError('policy/model/client size differs')
    policy.validate_ring(64)
    pin=pin_backend(Path(installation).resolve()); semantic=backend_contract(pin)
    output=Path(output).resolve(); output.mkdir(parents=True,exist_ok=False)
    shutil.copyfile(source,output/'model.py')
    workspace=output/'mpc'; workspace.mkdir()
    config={**asdict(policy),'clients':clients,'parties':4,'backend':'rep4','ring_bits':64,'backend_prime':1<<64,
        'domain_modulus':1<<64,'seed_encoding':'packed64','rep4_input_mode':'replicated-triples-v1',
        'output_mode':'native-public','output_length':0,'coordinate_circuit':'chunked',
        'chunk_blocks':64 if policy.dimension>=512 else 4,'round_slots':rounds,'widths':policy.widths(),
        'client_port':client_port,'runtime_client_port':True,'certified_stream':True,
        'backend_pin_hash':digest(semantic),'snapshot_version':2,'mask_mode':MASK_MODE,
        'component_input':'holder-checked-direct-v1','public_agreement':'checked-open-v1',
        'collection_window_ms':collection_window_ms,'mask_source_sha256':local_source_hashes()}
    write(workspace/'policy.json',config)
    sources=stage_circuit_sources(workspace)
    circuits=workspace/'Programs/Circuits'; circuits.mkdir(); (circuits/'aes_128.txt').write_bytes(circuit_bytes(Path(installation)))
    compilation=compile_circuit(workspace,Path(installation),config,sources,CIRCUIT_SHA256,Path.home()/'.cache/trustlessfl/circuits')
    files=artifacts(workspace)
    body={'protocol':PROTOCOL,'session_id':uuid.uuid4().hex,'peers':peers,'clients':clients,
        'rounds':rounds,'timeout':timeout,'config':config,'sources':sources,'artifacts':files,
        'aes_sha256':CIRCUIT_SHA256,'backend_contract':semantic,'model_adapter':model_contract(spec),
        'training':{'mode':'custom-model','seed':seed,**public_training(cfg.get('training',{}))},
        'initial_model':initial,'party_port':party_port,'client_port':client_port,'rpc_port':rpc_port,'fleet_port':fleet_port,
        'compilation':compilation,'trusted_test_audit':False}
    from .seed_mpc_app_guard import package_manifest
    body['app_sources']=package_manifest()
    write(output/'plan.json',body)
    return {'contract_hash':digest(body),'public_bundle':str(output)}


def check_plan(bundle,expected):
    bundle=Path(bundle).resolve(); body=read(bundle/'plan.json')
    if body.get('protocol')!=PROTOCOL or digest(body)!=expected: raise ProtocolError('public contract fingerprint differs')
    if body.get('trusted_test_audit') is not False: raise ProtocolError('distributed raw audit forbidden')
    from .seed_mpc_app_guard import package_manifest
    if body.get('app_sources')!=package_manifest(): raise ProtocolError('local app code differs from public contract')
    for i,peer in enumerate(body['peers']):
        safe_host(peer['host'])
        cert=checked_certificate(peer['certificate'],f'P{i}')
        if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value!=f'P{i}': raise ProtocolError('wrong certificate slot')
    if len(body['peers'])!=4: raise ProtocolError('four operator peers required')
    workspace=bundle/'mpc'
    if read(workspace/'policy.json')!=body['config'] or artifacts(workspace)!=body['artifacts']:
        raise ProtocolError('public circuit/config differs')
    if sha(workspace/'Programs/Circuits/aes_128.txt')!=CIRCUIT_SHA256 or sha(bundle/'model.py')!=body['model_adapter']['plugin_sha256']:
        raise ProtocolError('public model/AES differs')
    policy=SeedMPCPolicy(**{k:body['config'][k] for k in SeedMPCPolicy.__dataclass_fields__}); policy.validate_ring(64)
    if body['config']['backend_pin_hash']!=digest(body['backend_contract']) or body['config']['mask_source_sha256']!=local_source_hashes():
        raise ProtocolError('runtime semantics differ')
    from .seed_mpc_assets import stage_circuit_sources
    with tempfile.TemporaryDirectory(prefix='trustlessfl-source-check-') as scratch:
        if stage_circuit_sources(Path(scratch))!=body['sources']: raise ProtocolError('packaged circuit sources differ')
    for relative,expected_sha in body['sources'].items():
        if sha(workspace/'Programs/Source'/relative)!=expected_sha: raise ProtocolError('public circuit source changed')
    return body


def approve(directory,bundle,expected,installation):
    directory=Path(directory).resolve(); body=check_plan(bundle,expected)
    identity=Identity.from_private(read(directory/'identity.json')); slot=int(identity.name[1:])
    if identity.public()!=body['peers'][slot]['public'] or (directory/f'P{slot}.pem').read_text()!=body['peers'][slot]['certificate']:
        raise ProtocolError('operator identity differs from reviewed contract')
    pin=pin_backend(Path(installation).resolve())
    if backend_contract(pin)!=body['backend_contract']: raise ProtocolError('local backend semantics differ')
    # A0's bytecode hashes alone do not prove that the code enforces the policy.
    # Each operator independently compiles trusted packaged sources and compares.
    with tempfile.TemporaryDirectory(prefix='trustlessfl-review-') as scratch:
        work=Path(scratch); write(work/'policy.json',body['config'])
        sources=stage_circuit_sources(work)
        circuits=work/'Programs/Circuits'; circuits.mkdir()
        (circuits/'aes_128.txt').write_bytes(circuit_bytes(Path(installation)))
        compile_circuit(work,Path(installation),body['config'],sources,CIRCUIT_SHA256)
        if artifacts(work)!=body['artifacts']: raise ProtocolError('independent circuit compilation differs')
    approval=identity.sign({'protocol':PROTOCOL,'kind':'operator-contract-approval','contract_hash':expected})
    write(directory/'approval.json',approval)
    write(directory/'local-backend.json',{'installation':str(Path(installation).resolve()),'pin':pin},private=True)
    return {'approved':True,'contract_hash':expected,'operator':identity.name}


def provision_client(directory,bundle,expected,slot,train_data,installation,model_plugin):
    from .seed_mpc_client_app import provision
    body=check_plan(bundle,expected)
    if sha(model_plugin)!=body['model_adapter']['plugin_sha256']:
        raise ProtocolError('client-authorized local model differs from agreed model')
    from .seed_mpc_registration import TRANSPORT
    if type(slot) is not int or not 0<=slot<body['clients']: raise ProtocolError('client slot outside roster')
    directory=Path(directory).resolve()
    preparation={'client_count':body['clients'],'mask_mode':MASK_MODE,'snapshot_version':2,
        'session_id':body['session_id'],'execution_hash':expected,'policy_hash':SeedMPCPolicy(**{k:body['config'][k] for k in SeedMPCPolicy.__dataclass_fields__}).policy_hash,
        'installation':None,'registration_transport':TRANSPORT,'aggregator_public':{f'A{i}':p['public'] for i,p in enumerate(body['peers'])}}
    provision(directory,preparation,slot,test_audit=False)
    shutil.copyfile(model_plugin,directory/'authorized-model.py')
    shutil.copyfile(train_data,directory/'train.npz'); (directory/'train.npz').chmod(0o600)
    pem=certificate(directory,f'C{slot}',f'C{slot}')
    identity=Identity.from_private(read(directory/'client.json')['identity']); registration=read(directory/'public-registration.json')
    statement={'protocol':PROTOCOL,'kind':'client-enrollment','contract_hash':expected,
        'slot':slot,'registration':registration,'certificate':pem}
    write(directory/'enrollment.json',{'body':statement,'proof':identity.sign(statement)})
    return {'client':identity.name,'enrollment':str(directory/'enrollment.json')}


def finalize(bundle,expected,approvals,enrollments):
    bundle=Path(bundle).resolve(); body=check_plan(bundle,expected)
    registry={f'A{i}':p['public'] for i,p in enumerate(body['peers'])}
    if len(approvals)!=4 or len(enrollments)!=body['clients']: raise ProtocolError('incomplete public enrollment')
    checked=[]
    for i,path in enumerate(approvals):
        packet=read(path)
        if verify(packet,registry,sender=f'A{i}')!={'protocol':PROTOCOL,'kind':'operator-contract-approval','contract_hash':expected}:
            raise ProtocolError('operator contract approval differs')
        checked.append(packet)
    registrations=[]; certificates=[]; client_proofs=[]
    for slot,path in enumerate(enrollments):
        item=read(path); c=item['body']; name=f'C{slot}'
        if c.get('protocol')!=PROTOCOL or c.get('kind')!='client-enrollment' or c.get('contract_hash')!=expected or c.get('slot')!=slot:
            raise ProtocolError('client enrollment contract differs')
        registry[name]=c['registration']['public']
        if verify(item['proof'],registry,sender=name)!=c: raise ProtocolError('client certificate binding differs')
        cert=checked_certificate(c['certificate'],name)
        if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value!=name: raise ProtocolError('client TLS slot differs')
        registrations.append(c['registration']['envelope']); certificates.append(c['certificate']); client_proofs.append(item)
    policy={k:body['config'][k] for k in SeedMPCPolicy.__dataclass_fields__}
    deployment={'protocol':'seed-mpc-local-deployment-v1','distributed_session':PROTOCOL,
        'contract_hash':expected,'mask_mode':MASK_MODE,'mask_source_sha256':body['config']['mask_source_sha256'],
        'trusted_test_audit':False,'role_isolation':True,'aes_sha256':CIRCUIT_SHA256,
        'artifacts':body['artifacts'],'program':'seed_mpc_chunked_session-policy.json',
        'party_port':body['party_port'],'services':[f"https://{p['host']}:{body['rpc_port']}" for p in body['peers']],
        'timeout':body['timeout'],'rounds':body['rounds'],'training':body['training'],'initial_model':body['initial_model'],
        'test_fault':None,'model_adapter':body['model_adapter'],'compilation':body['compilation'],
        'approvals':checked,'client_certificates':certificates,'client_enrollments':client_proofs,
        'committee':{'policy':policy,'session_id':body['session_id'],'epoch':1,'snapshot_version':2,
            'collection_window_ms':body['config']['collection_window_ms'],'clients':[f'C{i}' for i in range(body['clients'])],
            'aggregators':[f'A{i}' for i in range(4)],'registry':registry,'registrations':registrations,'execution_hash':expected}}
    from .seed_mpc_committee import SeedCommittee
    c=deployment['committee']
    SeedCommittee(SeedMPCPolicy(**policy),c['session_id'],1,c['clients'],c['aggregators'],registry,registrations,expected,
        body['initial_model'],snapshot_version=2,collection_window_ms=c['collection_window_ms'])
    write(bundle/'deployment-public.json',deployment)
    return {'finalized':True,'public_deployment_hash':digest(deployment),'contract_hash':expected}


def tls_data(directory,body,public,own_name):
    data=directory/'Player-Data'; data.mkdir(mode=0o700)
    pems={f'P{i}':p['certificate'] for i,p in enumerate(body['peers'])}
    pems.update({f'C{i}':pem for i,pem in enumerate(public['client_certificates'])})
    for name,pem in pems.items(): (data/f'{name}.pem').write_text(pem)
    shutil.copyfile(directory/f'{own_name}.key',data/f'{own_name}.key'); (data/f'{own_name}.key').chmod(0o600)
    subprocess.run(['/usr/bin/openssl','rehash',str(data)],check=True,capture_output=True)
    (directory/'rpc-roots.pem').write_text(''.join(p['certificate'] for p in body['peers']))


def bind(directory,bundle,expected,*,expected_deployment,seed_packets=None,test_data=None):
    directory=Path(directory).resolve(); bundle=Path(bundle).resolve(); body=check_plan(bundle,expected)
    public=read(bundle/'deployment-public.json')
    if digest(public)!=expected_deployment or public.get('contract_hash')!=expected: raise ProtocolError('public enrollment fingerprint differs')
    identity=Identity.from_private(read(directory/'identity.json')) if (directory/'identity.json').exists() else Identity.from_private(read(directory/'client.json')['identity'])
    is_aggregator=identity.name.startswith('A'); slot=int(identity.name[1:]); own_name=f'P{slot}' if is_aggregator else identity.name
    if public['committee']['registry'][identity.name]!=identity.public(): raise ProtocolError('role public key differs')
    target=directory/'public'; target.mkdir()
    # Allowlist prevents accidental transfer of a role's private files in a bundle.
    for relative in ('plan.json','deployment-public.json','model.py','mpc/policy.json',
            'mpc/Programs/Circuits/aes_128.txt',
            *(f'mpc/Programs/Source/{name}' for name in body['sources']),
            *(f'mpc/Programs/{name}' for name in body['artifacts'])):
        source=bundle/relative; dest=target/relative
        if source.is_symlink(): raise ProtocolError('symlinked public bundle input')
        dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(source,dest)
    tls_data(directory,body,public,own_name)
    installation=None; pin=None
    if is_aggregator:
        installation=read(directory/'local-backend.json')['installation']
        pin=pin_backend(Path(installation))
        if backend_contract(pin)!=body['backend_contract']: raise ProtocolError('local executable semantics differ')
    config=body['config']
    write(directory/'registration-config.json',{**config,'party_hosts':[p['host'] for p in body['peers']]})
    (directory/'party-hosts.txt').write_text(''.join(p['host']+'\n' for p in body['peers']))
    d={**public,'public_bundle':str(target),'public_deployment_hash':expected_deployment,
        'workspace':str(target/'mpc'),'model_adapter':{**body['model_adapter'],'plugin':str(target/'model.py')},
        'native_binary':str(Path(installation)/'rep4-ring-party.x') if is_aggregator else None,'backend_pin':pin,
        'backend_contract_hash':digest(body['backend_contract']),'binary_sha256':pin['binary_sha256'] if is_aggregator else None,
        'config_sha256':sha(target/'mpc/policy.json'),'rpc_bind':'0.0.0.0',
        'rpc_transport':{'certificate':str(directory/f'{own_name}.pem'),'key':str(directory/f'{own_name}.key'),
            'roots':str(directory/'rpc-roots.pem'),'peers':{f"https://{p['host']}:{body['rpc_port']}":cert_fingerprint(p['certificate']) for p in body['peers']},
            'coordinator_fingerprint':cert_fingerprint(body['peers'][0]['certificate'])}}
    if not is_aggregator:
        d['model_adapter']['plugin']=str(directory/'authorized-model.py')
    if test_data:
        if not is_aggregator or slot!=0: raise ProtocolError('evaluation data belongs to A0 only')
        shutil.copyfile(test_data,directory/'public-test.npz'); d['test_data']=str(directory/'public-test.npz')
    if is_aggregator:
        if seed_packets is None or len(seed_packets)!=body['clients']: raise ProtocolError('recipient seed packets required')
        seeds=directory/'seed-packets'; seeds.mkdir(mode=0o700)
        for client,packet in enumerate(seed_packets): shutil.copyfile(packet,seeds/f'C{client}.json')
        (directory/'Programs').symlink_to(target/'mpc/Programs',target_is_directory=True)
    write(directory/'deployment.json',d,private=True)
    if is_aggregator:
        write(directory/'service-private.json',{'identity':identity.private(),'actor':str(directory),
            'deployment_sha256':sha(directory/'deployment.json')},private=True)
        role={'role':'aggregator','slot':slot,'deployment':str(directory/'deployment.json'),'private':str(directory/'service-private.json')}
    else:
        from .seed_mpc_client_app import pin as pin_client
        pin_client(directory,directory/'deployment.json')
        role={'role':'client','slot':slot,'deployment':str(directory/'deployment.json'),'client-directory':str(directory)}
    write(directory/'role.json',{'protocol':'seed-mpc-role-config-v1','distributed_session':PROTOCOL,**role},private=True)
    validate_local_deployment(d)
    return {'bound':True,'role':identity.name,'contract_hash':expected}


def cert_fingerprint(pem):
    return x509.load_pem_x509_certificate(pem.encode()).fingerprint(hashes.SHA256()).hex()


def validate_local_deployment(d):
    if d.get('distributed_session')!=PROTOCOL: raise ProtocolError('invalid remote protocol')
    body=check_plan(d['public_bundle'],d['contract_hash']); public=read(Path(d['public_bundle'])/'deployment-public.json')
    if digest(public)!=d['public_deployment_hash']: raise ProtocolError('public enrollment changed')
    expected={'contract_hash':d['contract_hash'],'mask_mode':MASK_MODE,
        'mask_source_sha256':body['config']['mask_source_sha256'],'trusted_test_audit':False,
        'role_isolation':True,'aes_sha256':CIRCUIT_SHA256,'artifacts':body['artifacts'],
        'party_port':body['party_port'],'timeout':body['timeout'],'rounds':body['rounds'],
        'training':body['training'],'initial_model':body['initial_model'],'model_adapter':body['model_adapter'],
        'program':'seed_mpc_chunked_session-policy.json',
        'services':[f"https://{p['host']}:{body['rpc_port']}" for p in body['peers']]}
    if any(public.get(k)!=v for k,v in expected.items()): raise ProtocolError('final enrollment differs from approved plan')
    c=public['committee']
    expected_committee={'policy':{k:body['config'][k] for k in SeedMPCPolicy.__dataclass_fields__},
        'session_id':body['session_id'],'epoch':1,'snapshot_version':2,
        'collection_window_ms':body['config']['collection_window_ms'],'execution_hash':d['contract_hash'],
        'clients':[f'C{i}' for i in range(body['clients'])],'aggregators':[f'A{i}' for i in range(4)]}
    if any(c.get(k)!=v for k,v in expected_committee.items()): raise ProtocolError('final committee differs from approved plan')
    if len(public['client_enrollments'])!=body['clients'] or len(public['client_certificates'])!=body['clients']:
        raise ProtocolError('incomplete client enrollment')
    for k,v in public.items():
        if k=='model_adapter':
            if model_contract(d[k])!=v: raise ProtocolError('local model projection differs')
        elif d.get(k)!=v: raise ProtocolError('local public contract projection differs')
    registry=public['committee']['registry']
    for slot,packet in enumerate(public['approvals']):
        if verify(packet,registry,sender=f'A{slot}')!={'protocol':PROTOCOL,'kind':'operator-contract-approval','contract_hash':d['contract_hash']}:
            raise ProtocolError('missing reviewed committee approval')
    if len(public['approvals'])!=4: raise ProtocolError('four committee approvals required')
    for slot,item in enumerate(public['client_enrollments']):
        b=item['body']; name=f'C{slot}'
        checked_certificate(b['certificate'],name)
        if (verify(item['proof'],registry,sender=name)!=b or b['contract_hash']!=d['contract_hash'] or b['slot']!=slot
                or b['certificate']!=public['client_certificates'][slot] or b['registration']['envelope']!=public['committee']['registrations'][slot]
                or b['registration']['public']!=registry[name]): raise ProtocolError('client enrollment differs')
    for slot,peer in enumerate(body['peers']):
        if registry[f'A{slot}']!=peer['public']: raise ProtocolError('operator registry differs')
    expected_peers={f"https://{p['host']}:{body['rpc_port']}":cert_fingerprint(p['certificate']) for p in body['peers']}
    transport=d['rpc_transport']
    if transport['peers']!=expected_peers or transport['coordinator_fingerprint']!=cert_fingerprint(body['peers'][0]['certificate']):
        raise ProtocolError('network identity projection differs')
    if d['backend_contract_hash']!=digest(body['backend_contract']): raise ProtocolError('local backend contract differs')


def check_client_role(path):
    from .seed_mpc_session import load_deployment
    role=read(path)
    if role.get('distributed_session')!=PROTOCOL or role.get('role')!='client': raise ProtocolError('remote client config required')
    d,c=load_deployment(role['deployment']); private=read(Path(role['client-directory'])/'client.json')
    identity=Identity.from_private(private['identity'])
    if (private.get('test_audit') is not False or private['deployment_sha256']!=sha(role['deployment'])
            or private['deployment']!=role['deployment'] or identity.name!=c.clients[role['slot']]
            or identity.public()!=c.registry[identity.name]): raise ProtocolError('remote client binding differs')
    return role


def server_tls(d,slot):
    t=d['rpc_transport']; context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_2; context.verify_mode=ssl.CERT_REQUIRED
    context.load_cert_chain(t['certificate'],t['key']); context.load_verify_locations(cafile=t['roots'])
    return context


class DistributedHTTPServer(HTTPServer):
    def __init__(self,address,handler,context):
        self.tls_context=context
        super().__init__(address,handler)

    def get_request(self):
        sock,address=super().get_request()
        sock.settimeout(10)
        try:
            return self.tls_context.wrap_socket(sock,server_side=True),address
        except BaseException:
            sock.close(); raise


def authorize_rpc_peer(connection,d):
    return hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()==d['rpc_transport']['coordinator_fingerprint']


def remote_rpc(url,action,payload,*,timeout,meter,transport):
    if url not in transport['peers'] or not re.fullmatch(r'[a-z-]+',action): raise ProtocolError('unapproved remote RPC endpoint')
    parsed=urlsplit(url)
    if parsed.scheme!='https' or parsed.path or parsed.username or parsed.password: raise ProtocolError('HTTPS required')
    context=ssl.create_default_context(cafile=transport['roots']); context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(transport['certificate'],transport['key'])
    connection=http.client.HTTPSConnection(parsed.hostname,parsed.port,timeout=timeout,context=context)
    data=canonical(payload or {}); scope=meter.scope if meter else None
    try:
        connection.connect()
        if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()!=transport['peers'][url]:
            raise ProtocolError('RPC peer fingerprint differs')
        if meter: meter.record('aggregator-rpc-json','sent',action,len(data),scope=scope)
        connection.request('POST','/'+action,body=data,headers={'Content-Type':'application/json'})
        response=connection.getresponse(); raw=response.read(16*1024*1024+1)
        if meter: meter.record('aggregator-rpc-json','received',action,len(raw),scope=scope)
        if response.status!=200 or len(raw)>16*1024*1024: raise ProtocolError('remote RPC rejected')
        body=json.loads(raw)
        if set(body)!={'result'}: raise ProtocolError('malformed RPC result')
        return body['result']
    except ProtocolError:
        raise
    except (OSError,ValueError,http.client.HTTPException) as exc:
        raise ProtocolError('authenticated remote RPC failed; no plaintext fallback') from exc
    finally: connection.close()


def runtime(directory,command):
    """Run only this host's role. Local AppIO/Control are bound to loopback."""
    directory=Path(directory).resolve(); role=read(directory/'role.json')
    from .seed_mpc_session import load_deployment
    d,c=load_deployment(role['deployment']); body=read(Path(d['public_bundle'])/'plan.json')
    env={**os.environ,'FLWR_HOME':str(directory/'flower-home'),'FLWR_TELEMETRY_ENABLED':'0',
        'FLWR_DISABLE_UPDATE_CHECK':'1','OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1','MKL_NUM_THREADS':'1'}
    if command=='aggregator':
        if role['role']!='aggregator': raise ProtocolError('aggregator role required')
        write(directory/'native-started.json',{'protocol':PROTOCOL,'started_ns':time.time_ns()},private=True)
        argv=[sys.executable,'-m','trustlessfl.seed_mpc_service','--deployment',role['deployment'],'--private',role['private'],'--slot',str(role['slot'])]
    elif command=='client':
        check_client_role(directory/'role.json')
        from .seed_mpc_app_guard import bootstrap
        bootstrap(directory,env)
        argv=['flower-supernode','--root-certificates',str(directory/'Player-Data/P0.pem'),
            '--superlink',f"{body['peers'][0]['host']}:{body['fleet_port']}",
            '--node-config',f'client-config="{directory / "role.json"}"',
            '--host','127.0.0.1','--port','19000','--max-wait-time',str(d['timeout'])]
    elif command=='superlink':
        if role['role']!='aggregator' or role['slot']!=0: raise ProtocolError('A0 required')
        argv=['flower-superlink','--ssl-certfile',str(directory/'P0.pem'),'--ssl-keyfile',str(directory/'P0.key'),
            '--ssl-ca-certfile',str(directory/'P0.pem'),'--fleet-api-address',f"0.0.0.0:{body['fleet_port']}",
            '--control-api-address','127.0.0.1:19001','--host','127.0.0.1','--port','19002',
            '--isolation','subprocess','--disable-runtime-dependency-installation']
    else: raise ProtocolError('unknown role runtime')
    subprocess.run(argv,env=env,cwd=directory,check=True)


def flower_run(directory):
    directory=Path(directory).resolve(); role=read(directory/'role.json')
    if role['role']!='aggregator' or role['slot']!=0: raise ProtocolError('A0 required')
    from .seed_mpc_session import load_deployment
    d,c=load_deployment(role['deployment'])
    write(directory/'flower-started.json',{'protocol':PROTOCOL,'started_ns':time.time_ns()},private=True)
    app=directory/'app'; app.mkdir()
    shutil.copytree(Path(__file__).parent,app/'trustlessfl',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    config={'deployment-file':role['deployment'],'output-dir':str(directory/'runtime-results')}
    pyproject={'project':{'name':'trustlessfl','version':'0.1.0','description':'Independent Seed-MPC roles',
        'license':'MIT','requires-python':'>=3.12','dependencies':['flwr==1.36.0','numpy>=2.5.0','cryptography>=46.0.7,<47']},
        'tool':{'flwr':{'app':{'publisher':'trustlessfl','components':{'serverapp':'trustlessfl.seed_mpc_server_app:app',
            'clientapp':'trustlessfl.seed_mpc_client_app:app'},'config':config}}}}
    (app/'pyproject.toml').write_text(tomli_w.dumps(pyproject))
    home=directory/'flower-home'; home.mkdir(exist_ok=True)
    (home/'config.toml').write_text(tomli_w.dumps({'superlink':{'default':'local-control','local-control':{
        'address':'127.0.0.1:19001','root-certificates':str(directory/'P0.pem')}}}))
    env={**os.environ,'FLWR_HOME':str(home),'FLWR_TELEMETRY_ENABLED':'0','FLWR_DISABLE_UPDATE_CHECK':'1'}
    subprocess.run(['flwr','run',str(app),'local-control','--stream'],env=env,cwd=app,check=True,timeout=d['timeout']*d['rounds']+600)
    from .seed_mpc_launcher import require_completed_run
    result=subprocess.run(['flwr','list','--format','json'],env=env,capture_output=True,text=True,check=True,timeout=30)
    require_completed_run(json.loads(result.stdout))
    write(directory/'flower-run-status.json',json.loads(result.stdout))


def main():
    parser=argparse.ArgumentParser(description=__doc__); commands=parser.add_subparsers(dest='command',required=True)
    p=commands.add_parser('init-aggregator'); p.add_argument('--directory',type=Path,required=True); p.add_argument('--slot',type=int,required=True); p.add_argument('--host',required=True)
    p=commands.add_parser('plan'); p.add_argument('--output',type=Path,required=True); p.add_argument('--mp-spdz-dir',dest='installation',type=Path,required=True)
    p.add_argument('--model-config',type=Path,required=True); p.add_argument('--peers',dest='peer_files',type=Path,nargs=4,required=True); p.add_argument('--clients',type=int,required=True)
    p.add_argument('--rounds',type=int,default=2); p.add_argument('--seed',type=int,default=42); p.add_argument('--collection-window-ms',type=int,default=30000)
    p.add_argument('--timeout',type=int,default=300)
    for flag,default in (('party-port',15000),('client-port',16000),('rpc-port',17000),('fleet-port',18000)):
        p.add_argument('--'+flag,type=int,default=default)
    for name in ('approve','client-prepare','finalize','bind'):
        p=commands.add_parser(name); p.add_argument('--bundle',type=Path,required=True); p.add_argument('--expected-contract-hash',dest='expected',required=True)
        if name!='finalize': p.add_argument('--directory',type=Path,required=True)
        if name=='approve': p.add_argument('--mp-spdz-dir',dest='installation',type=Path,required=True)
        if name=='client-prepare': p.add_argument('--mp-spdz-dir',dest='installation',type=Path,help=argparse.SUPPRESS)
        if name=='client-prepare':
            p.add_argument('--slot',type=int,required=True); p.add_argument('--train-data',type=Path,required=True)
            p.add_argument('--model-plugin',type=Path,required=True,help='client-authorized local model source')
        if name=='finalize': p.add_argument('--approvals',nargs=4,type=Path,required=True); p.add_argument('--enrollments',nargs='+',type=Path,required=True)
        if name=='bind': p.add_argument('--expected-deployment-hash',dest='expected_deployment',required=True); p.add_argument('--seed-packets',nargs='+',type=Path); p.add_argument('--test-data',type=Path)
    for name in ('aggregator','client','superlink','flower-run'):
        commands.add_parser(name).add_argument('--directory',type=Path,required=True)
    args=vars(parser.parse_args()); command=args.pop('command')
    if command in ('aggregator','client','superlink'): runtime(command=command,**args); return
    if command=='flower-run': flower_run(**args); return
    function={'init-aggregator':init_aggregator,'plan':plan,'approve':approve,'client-prepare':provision_client,'finalize':finalize,'bind':bind}[command]
    print(json.dumps(function(**args),ensure_ascii=False))


if __name__=='__main__': main()

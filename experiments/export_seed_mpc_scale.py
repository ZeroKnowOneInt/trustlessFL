"""Allowlisted public scale-run archives and application-content accounting."""
import argparse
import hashlib
import json
from pathlib import Path

from trustlessfl.crypto import ProtocolError,canonical


def communication(body):
    masked=requests=responses=commits=0
    for decision in body['records']:
        manifest=decision['manifest']; iq=decision['input_certificate']; rq=decision['result_certificate']
        rows={}
        for packet in manifest['inputs']: rows.setdefault(packet['sender'],[]).append(packet)
        masked+=sum(len(canonical(packets))+len('envelopes') for packets in rows.values())
        requests+=4*sum(len(canonical(payload)) for payload in (
            {'manifest':manifest},{'manifest':manifest,'input_certificate':iq},
            {'manifest':manifest,'result_certificate':rq}))
        responses+=sum(len(canonical({'result':vote})) for vote in [*iq['votes'],*rq['votes']])
        responses+=4*len(canonical({'result':True}))
        commits+=8*(len(canonical(decision))+len('json'))
    return {'scope':'recorded application contents, excluding framing/TLS/HTTP/Flower protobuf and registration/identity/ack/ready/finish control messages',
        'native_all_party_decimal_mb':body['internal_mb'],'masked_configrecord_content_bytes':masked,
        'aggregator_round_rpc_request_json_bytes':requests,'aggregator_round_rpc_response_json_bytes':responses,
        'client_commit_configrecord_content_bytes_including_duplicate_test':commits,
        'public_model_array_raw_bytes_train_and_two_commits':body['dimension']*8*4*3*body['rounds'],
        'duplicate_commit_test_included':True}


def export_run(source,destination):
    body_path=list((source/'runtime-results').glob('run-*/results.json'))
    if len(body_path)!=1: raise ProtocolError('missing unique run result')
    body=json.loads(body_path[0].read_text())
    verification_path=max(source.glob('verification*.json'),key=lambda p:p.stat().st_mtime_ns)
    verification=json.loads(verification_path.read_text())
    verifier=Path(__file__).with_name('run_seed_mpc_flower.py')
    if hashlib.sha256(verifier.read_bytes()).hexdigest()!=verification['verification_source_sha256']:
        raise ProtocolError('archive needs verification by the current oracle')
    if verification['passed'] is not True: raise ProtocolError('unverified scale run')
    destination.mkdir(parents=True,exist_ok=False)
    files={name:source/name for name in ['deployment.json','provenance.json','verification.json']}
    files['verification.json']=verification_path; files['verifier-source.py']=verifier
    if (source/'dataset.json').exists(): files['dataset.json']=source/'dataset.json'
    files.update({'results.json':body_path[0],'compile.log':source/'mpc/compile.log',
                  'compile-resource.txt':source/'mpc/compile-resource.txt','policy.json':source/'mpc/policy.json'})
    attempts=list(source.glob('attempt-*'))
    if len(attempts)!=1: raise ProtocolError('ambiguous official runtime attempt')
    for name in ['flwr.log','superlink.log','timing.json']: files[name]=attempts[0]/name
    for i in range(4):
        for name in ['native.log','service.log','native-resource.txt']: files[f'P{i}-{name}']=source/f'mpc/P{i}'/name
        files[f'C{i}-client.log']=source/f'clients/C{i}/client.log'
    for path in (source/'sources').rglob('*.py'): files['sources/'+str(path.relative_to(source/'sources'))]=path
    for path in (source/'mpc/Programs/Source').iterdir():
        if path.is_file(): files['mpc-source/'+path.name]=path
    # Never copy client audits, AES seeds, signing/TLS keys, SQLite or shares.
    # Fail before writing a file if even its public log contains a test secret.
    secrets=[]
    for path in [*(source/'clients').glob('C*/client.json'),*(source/'mpc').glob('P*/service-private.json')]:
        private=json.loads(path.read_text())
        if 'seed_key' in private: secrets.append(private['seed_key'].encode())
        secrets.extend(v.encode() for v in private['identity'].values() if isinstance(v,str) and len(v)>=64)
    hashes={}
    for name,path in files.items():
        data=path.read_bytes()
        if any(secret in data for secret in secrets): raise ProtocolError('private value in export candidate')
        target=destination/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
        hashes[name]=hashlib.sha256(data).hexdigest()
    status=json.loads((attempts[0]/'run-status.json').read_text())
    # Exception/status detail strings are deliberately excluded.
    safe={'success':status['success'],'runs':[{k:r[k] for k in ['run-id','status','elapsed','compute-time']} for r in status['runs']]}
    if safe['success'] is not True or len(safe['runs'])!=1 or safe['runs'][0]['status']!='finished:completed':
        raise ProtocolError('official run not completed')
    for name,value in [('communication.json',communication(body)),('run-status.json',safe)]:
        data=canonical(value); (destination/name).write_bytes(data); hashes[name]=hashlib.sha256(data).hexdigest()
    return {'verification':verification,'file_sha256':hashes}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory',type=Path,required=True)
    parser.add_argument('--run',nargs=2,action='append',metavar=('NAME','DIRECTORY'),required=True)
    args=parser.parse_args(); args.output_directory.mkdir(parents=True,exist_ok=False)
    summary={'scope':'actual Rep4 plus official Flower; single WSL UID; each verified run records its synthetic or actual learning mode',
             'runs':{}}
    for name,directory in args.run:
        if not name or Path(name).name!=name or name in summary['runs']: raise ProtocolError('invalid archive name')
        summary['runs'][name]=export_run(Path(directory),args.output_directory/name)
    (args.output_directory/'summary.json').write_bytes(canonical(summary))
    print(json.dumps({name:run['verification'] for name,run in summary['runs'].items()},indent=2))


if __name__=='__main__': main()

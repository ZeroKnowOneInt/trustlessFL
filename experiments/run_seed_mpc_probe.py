"""Four-party active secret-AES fixtures; not Flower or a production service."""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import urllib.request
import uuid

from experiments.run_private_bound_mpc import configure_tls, free_port_base, write_private
from trustlessfl.crypto import ProtocolError, digest
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_wire import aes_blocks, mask_words, reference_aggregate

ROOT = Path(__file__).resolve().parents[1]
CIRCUIT_COMMIT = '1603ed6aa12348c2ef15ed8395b9b96e4c558b7f'
CIRCUIT_SHA256 = '40423a0cdaf5d4d34aba872c12660f115dc25c12eea6e24a9304578e79df6d04'
CIRCUIT_URL = f'https://raw.githubusercontent.com/mkskeller/bristol-fashion/{CIRCUIT_COMMIT}/aes_128.txt'


def circuit_bytes(installation):
    source = installation/'Programs/Circuits/aes_128.txt'
    data = source.read_bytes() if source.exists() else urllib.request.urlopen(CIRCUIT_URL, timeout=30).read()
    if hashlib.sha256(data).hexdigest() != CIRCUIT_SHA256:
        raise ProtocolError('AES circuit hash differs from pinned artifact')
    return data


def build_fixture(case, dimension=2, word_bits=16):
    if case not in ('aes', 'multi-round', 'alternate', 'cross-chunk', 'edge-cases', 'nonboolean', 'nonboolean-high', 'equivocate', 'tamper-triple',
                    'public-equivocate', 'public-highbit', 'noncanonical-wire', 'nonzero-padding', 'replayed-round'):
        raise ProtocolError('unknown fixture')
    if type(dimension) is not int or not 2 <= dimension <= 4096:
        raise ProtocolError('probe dimension must be 2..4096; full-model runner is separate')
    policy = SeedMPCPolicy(dimension, 4, 20000, 400000000, scale=1, word_bits=word_bits)
    keys = [bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')] + [
        hashlib.sha256(f'PUBLIC SYNTHETIC seed fixture {i}'.encode()).digest()[:16] for i in range(1,4)]
    pad = lambda x: x + [0]*(dimension-len(x))
    updates = [[pad([20000,0]) for _ in range(4)],
               [pad([-20000,0]), pad([-20000,0]), pad([20001,1]), pad([20000,1])],
               [pad([20000,1]), pad([20001,0]), pad([20000,1]), pad([3,4])]]
    if case == 'alternate':
        updates = [[pad([-20000,0]) for _ in range(4)],
                   [pad([3,4]),pad([-3,-4]),pad([20001,0]),pad([20000,1])],
                   [pad([0,0]) for _ in range(4)]]
        # Exercise later chunks and the final partial chunk, not just coordinate 0.
        if dimension > 2:
            updates[1][0][-1] = 7
            updates[1][1][-1] = 9
            updates[2][2][-1] = 20001
    if case == 'cross-chunk':
        if dimension < 33: raise ProtocolError('cross-chunk fixture needs at least 33 coordinates')
        updates = [[[0]*dimension for _ in range(4)] for _ in range(3)]
        updates[0][0][0] = updates[0][0][-1] = 15000
        updates[0][1][0] = -20000; updates[0][2][-1] = 20000
        updates[1][0][0] = 20000; updates[1][1][-1] = -20000
        updates[1][2][0] = 20000; updates[1][2][-1] = 1
        updates[1][3][-1] = 20001
        for i in range(1,4): updates[2][i][-1] = 20001
    if case == 'edge-cases':
        half = policy.modulus//2
        updates = [[pad([-half,0]),pad([half-1,0]),pad([20000,0]),pad([-20000,0])],
                   [pad([0,0]),pad([0,0]),pad([20000,1]),pad([-20000,1])],
                   [pad([20001,0]),pad([-20001,0]),pad([19999,1]),pad([-19999,-1])],
                   [pad([-20000,0]) for _ in range(4)],
                   [pad([20000,0]) for _ in range(4)],
                   [pad([0,0]) for _ in range(4)]]
    rounds = []
    expected = []
    wraps = {'positive': 0, 'negative': 0}
    for r, inputs in enumerate(updates, 1):
        masks = [mask_words(k, r, dimension, word_bits) for k in keys]
        wire = [[(u+m)%policy.modulus for u,m in zip(row,mask)] for row,mask in zip(inputs,masks)]
        for row,mask in zip(inputs,masks):
            wraps['positive'] += sum(u+m >= policy.modulus for u,m in zip(row,mask))
            wraps['negative'] += sum(u+m < 0 for u,m in zip(row,mask))
        for row in wire: policy.validate_wire(row)
        rounds.append({'round_id':r,'wire':wire})
        expected.append(reference_aggregate(policy,keys,r,wire))
    if case == 'aes':
        block = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
        ciphertexts = [aes_blocks(k,[block]) for k in keys]
        expected = [int.from_bytes(c[j:j+4],'big') for c in ciphertexts for j in range(0,16,4)]
    return policy,keys,rounds,expected,wraps


def decode_outputs(config, values):
    if len(values) != config['output_length']:
        raise ProtocolError('incorrect MPC output length')
    if config['case'] == 'aes':
        if any(type(v) is not int or not 0<=v<2**32 for v in values):
            raise ProtocolError('invalid AES probe output')
        return values
    step = config['dimension']+2
    outputs = []
    for start in range(0,len(values),step):
        ok,count,*total = values[start:start+step]
        if ok == 0:
            if count or any(total): raise ProtocolError('abort revealed intermediate output')
            outputs.append({'status':'abort'})
        elif ok == 1:
            if not config['minimum_accepted']<=count<=config['clients']:
                raise ProtocolError('invalid accepted count')
            if any(abs(v)>config['clients']*config['coordinate_cap'] for v in total):
                raise ProtocolError('SUM exceeds capacity')
            outputs.append({'status':'ok','count':count,'sum':total})
        else:
            raise ProtocolError('invalid authenticated status')
    return outputs


def run_probe(installation,case='multi-round',timeout=600,dimension=2,communication_stats=False,profile_stages=False,
              backend='mascot',coordinate_circuit='arithmetic',seed_encoding=None,ring_bits=64,word_bits=16,
              native_public=False,chunk_blocks=4,compiled_workspace=None):
    chunked = coordinate_circuit == 'chunked'
    candidate = backend == 'rep4' or coordinate_circuit == 'binary' or native_public
    seed_encoding = seed_encoding or ('packed64' if backend == 'rep4' else 'bits')
    if backend not in ('mascot','rep4') or coordinate_circuit not in ('arithmetic','binary','chunked'):
        raise ProtocolError('unsupported candidate backend/circuit')
    if chunked and (backend != 'rep4' or ring_bits != 64 or case == 'aes'
                    or type(chunk_blocks) is not int or not 1<=chunk_blocks<=8):
        raise ProtocolError('chunked candidate requires Rep4/64 and 1..8 blocks')
    if not chunked and (compiled_workspace is not None or dimension > 64
                        or case in ('public-equivocate','public-highbit','noncanonical-wire','nonzero-padding','replayed-round')):
        raise ProtocolError('runtime input/reuse/large dimension requires chunked circuit')
    if seed_encoding not in ('bits','packed64') or (backend == 'mascot' and seed_encoding != 'bits'):
        raise ProtocolError('unsupported candidate seed encoding')
    if (candidate and profile_stages) or (case == 'nonboolean-high' and backend != 'rep4'):
        raise ProtocolError('unsupported candidate fixture mode')
    if case.startswith('nonboolean') and seed_encoding != 'bits':
        raise ProtocolError('Boolean rejection fixture requires bit encoding')
    if case in ('equivocate','tamper-triple') and backend != 'rep4':
        raise ProtocolError('Rep4 input adapter fixture requires Rep4')
    if profile_stages:
        if case != 'multi-round': raise ProtocolError('stage profiling requires multi-round fixture')
        communication_stats = True
    installation=Path(installation).resolve()
    harness_hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in [Path(__file__),ROOT/'trustlessfl/seed_mpc_external_client.py',
                              ROOT/'trustlessfl/seed_mpc_policy.py',ROOT/'trustlessfl/seed_mpc_wire.py',
                              ROOT/'trustlessfl/rep4_external.py']}
    binary=installation/('rep4-ring-party.x' if backend == 'rep4' else 'mascot-party.x')
    if not binary.is_file(): raise ProtocolError('pinned MPC binary missing')
    policy,keys,rounds,expected,wraps=build_fixture(case,dimension,word_bits)
    field=(1 << ring_bits) if backend == 'rep4' else policy.backend_prime()
    width=max(policy.widths().values())
    if case=='aes': width=max(width,34)
    if backend == 'rep4': policy.validate_ring(ring_bits)
    else: policy.validate_backend(field,width)
    workspace=ROOT/'.cache/seed-mpc/runs'/uuid.uuid4().hex
    workspace.mkdir(parents=True,mode=0o700)
    port=free_port_base(4); client_port=free_port_base(4)
    while abs(port-client_port)<8: client_port=free_port_base(4)
    config={**asdict(policy),'clients':4,'parties':4,'backend_prime':field,
            'backend':backend,'domain_modulus':field,'ring_bits':ring_bits if backend=='rep4' else None,
            'seed_encoding':seed_encoding,'coordinate_circuit':coordinate_circuit,
            'output_mode':'native-public' if candidate else 'external-clients',
            'rep4_input_mode':'replicated-triples-v1' if backend=='rep4' else None,
            'widths':policy.widths(),'client_port':client_port,'case':case,
            'test_counter':'6bc1bee22e409f96e93d7e117393172a',
            'rounds':rounds if case!='aes' else [],
            'output_length':16 if case=='aes' else len(rounds)*(dimension+2),
            'context':{'protocol':'seed-mpc-probe-v1','session':workspace.name,
                       'committee_epoch':1,'policy_hash':policy.policy_hash}}
    if chunked:
        config.update(rounds=[],round_slots=len(rounds),chunk_blocks=chunk_blocks)
    reused = None
    if compiled_workspace is not None:
        reused = Path(compiled_workspace).resolve()
        if not reused.is_relative_to((ROOT/'.cache/seed-mpc/runs').resolve()):
            raise ProtocolError('compiled workspace must be a local probe artifact')
        old = json.loads((reused/'policy.json').read_text())
        previous = json.loads((reused/'result.json').read_text())
        if previous['policy_hash'] != digest(old):
            raise ProtocolError('cached compilation manifest differs from recorded policy')
        contract = [*asdict(policy),'clients','parties','backend','ring_bits','seed_encoding',
                    'coordinate_circuit','round_slots','chunk_blocks','output_mode','rep4_input_mode']
        if any(old[k] != config[k] for k in contract):
            raise ProtocolError('compiled policy/shape differs from requested run')
        config['client_port'] = old['client_port']
    config_path=workspace/'policy.json'
    config_path.write_text(json.dumps(config))
    source_name='seed_aes_probe' if case=='aes' else 'seed_mpc_session'
    if candidate: source_name = 'seed_mpc_candidate_session'
    if candidate and case == 'aes': source_name = 'seed_mpc_candidate_aes'
    if chunked: source_name = 'seed_mpc_chunked_session'
    if profile_stages: source_name = 'seed_mpc_profile'
    src_dir=workspace/'Programs/Source'; src_dir.mkdir(parents=True)
    sources={}
    source_files = [source_name+'.mpc','seed_mpc_primitives.py']
    if candidate: source_files.append('seed_mpc_candidate_primitives.py')
    for name in source_files:
        data=(ROOT/'mpc/Programs/Source'/name).read_bytes()
        (src_dir/name).write_bytes(data); sources[name]=hashlib.sha256(data).hexdigest()
    cir_dir=workspace/'Programs/Circuits'; cir_dir.mkdir()
    (cir_dir/'aes_128.txt').write_bytes(circuit_bytes(installation))
    command=[sys.executable,str(installation/'compile.py'),'-X','-P',str(field),
             '-F',str(width),'-M',source_name,'policy.json']
    if backend == 'rep4':
        command=[sys.executable,str(installation/'compile.py'),'-R',str(ring_bits),'-Z','4',
                 '-M',source_name,'policy.json']
    compile_start=time.monotonic()
    if reused is None:
        with (workspace/'compile.log').open('w') as log:
            completed=subprocess.run(command,cwd=workspace,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        if completed.returncode:
            raise ProtocolError(f'compile failed: {workspace}/compile.log')
        compile_seconds=time.monotonic()-compile_start
    else:
        import shutil
        if previous['source_sha256'] != sources or previous['aes_circuit_sha256'] != CIRCUIT_SHA256:
            raise ProtocolError('compiled source artifact differs from current source')
        for folder in ('Bytecode','Schedules'):
            shutil.copytree(reused/'Programs'/folder,workspace/'Programs'/folder)
        shutil.copyfile(reused/'compile.log',workspace/'compile.log')
        compile_seconds=0.0
    program=source_name+'-policy.json'
    actors=configure_tls(workspace,4,4)
    if chunked:
        padded = ((dimension+chunk_blocks*(128//word_bits)-1)//(chunk_blocks*(128//word_bits)))*chunk_blocks*(128//word_bits)
        if case=='nonzero-padding' and padded==dimension:
            raise ProtocolError('padding fault fixture needs a partial chunk')
        stream=[]
        for item in rounds:
            stream.append(item['round_id'])
            for row in item['wire']: stream.extend(row+[0]*(padded-dimension))
        for i in range(4):
            programs=actors[f'P{i}']/'Programs'
            programs.unlink(); programs.mkdir()
            for folder in ('Bytecode','Schedules','Circuits'):
                (programs/folder).symlink_to(workspace/'Programs'/folder,target_is_directory=True)
            public=programs/'Public-Input'; public.mkdir()
            values=list(stream)
            if case=='public-equivocate' and i==2: values[1] ^= 1
            if case=='public-highbit' and i==2: values[1] += 1<<63
            if case=='noncanonical-wire': values[1] = policy.modulus
            if case=='nonzero-padding': values[1+dimension] = 1
            if case=='replayed-round': values[1+4*padded] = values[0]
            (public/program).write_text('\n'.join(map(str,values))+'\n')
        artifact_hash = digest({str(p.relative_to(workspace/'Programs')):hashlib.sha256(p.read_bytes()).hexdigest()
                               for folder in ('Bytecode','Schedules') for p in (workspace/'Programs'/folder).rglob('*') if p.is_file()})
        if reused is not None and artifact_hash != previous['compiled_artifact_hash']:
            raise ProtocolError('cached bytecode/schedule differs from recorded artifact')
    processes=[]; handles=[]
    try:
        for i in range(4):
            actor=actors[f'P{i}']; log=(actor/'native.log').open('w'); handles.append(log)
            args=[str(binary),'-e','-N','4','-pn',str(port),'-h','127.0.0.1',
                  '-P',str(field),'-p',str(i),program]
            if backend == 'rep4':
                args=[str(binary),'-pn',str(port),'-h','127.0.0.1','-R',str(ring_bits),'-p',str(i),program]
            if candidate: args.extend(['-OF','.'])
            if communication_stats: args.append('-v')
            processes.append(subprocess.Popen(args,cwd=actor,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
        for i,key in enumerate(keys):
            actor=actors[f'C{i}']; private=actor/'fixture-input.json'
            write_private(private,json.dumps({'client_id':i,'fixture_key':key.hex(),
                'mutation':case if (case.startswith('nonboolean') or case in ('equivocate','tamper-triple')) and i==2 else None}).encode())
            log=(actor/'client.log').open('w'); handles.append(log)
            env={**os.environ,'PYTHONPATH':str(ROOT),'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1'}
            args=[sys.executable,'-m','trustlessfl.seed_mpc_external_client','--mp-spdz-dir',str(installation),
                  '--private-input',str(private),'--config',str(config_path),'--output',str(actor/'pending-output.json')]
            if communication_stats:
                args.extend(['--communication-output',str(actor/'communication.json')])
            processes.append(subprocess.Popen(args,cwd=actor,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
        started=time.monotonic()
        while any(p.poll() is None for p in processes):
            if any(p.poll() not in (None,0) for p in processes): break
            if time.monotonic()-started>timeout:
                raise TimeoutError(f'native deadline exceeded: {workspace}')
            time.sleep(.1)
        failed=any(p.poll() != 0 for p in processes)
        if failed:
            for p in processes:
                if p.poll() is None: os.killpg(p.pid,signal.SIGTERM)
            for p in processes: p.wait(timeout=10)
            logs='\n'.join((actors[f'P{i}']/'native.log').read_text() for i in range(4))
            rejection = ('invalid Boolean seed input' if case.startswith('nonboolean') else
                         'inconsistent seed response' if case=='equivocate' else
                         'inconsistent public chunk' if case in ('public-equivocate','public-highbit') else
                         'noncanonical public wire' if case=='noncanonical-wire' else
                         'nonzero public padding' if case=='nonzero-padding' else
                         'replayed or invalid round counter' if case=='replayed-round' else
                         'inconsistent replicated triple components' if case=='tamper-triple' else None)
            if case=='tamper-triple': logs += (actors['C2']/'client.log').read_text()
            if rejection is None or rejection not in logs:
                raise ProtocolError(f'native fixture failed: {workspace}')
            if not candidate and any((actors[f'C{i}']/'pending-output.json').exists() for i in range(4)):
                raise ProtocolError('rejected seed produced output')
            if candidate and case!='replayed-round' and any('SEED_MPC_PUBLIC ' in (actors[f'P{i}']/'native.log').read_text() for i in range(4)):
                raise ProtocolError('rejected registration produced public output')
            if case=='replayed-round':
                for i in range(4):
                    emitted = re.findall(r'^SEED_MPC_PUBLIC (-?\d+)$',(actors[f'P{i}']/'native.log').read_text(),re.M)
                    if len(emitted)!=dimension+2 or decode_outputs({**config,'output_length':dimension+2},list(map(int,emitted))) != expected[:1]:
                        raise ProtocolError('replayed round emitted unexpected output')
            output={'status':'input-abort'}
        else:
            # Local harness rule. Real service needs post-check output certificates.
            pending=[json.loads((actors[f'C{i}']/'pending-output.json').read_text()) for i in range(4)]
            if any(v!=pending[0] for v in pending): raise ProtocolError('output disagreement')
            if candidate:
                public = [[int(v) for v in re.findall(r'^SEED_MPC_PUBLIC (-?\d+)$',
                          (actors[f'P{i}']/'native.log').read_text(),re.M)] for i in range(4)]
                if any(v != public[0] for v in public): raise ProtocolError('native public output disagreement')
                output=decode_outputs(config,public[0])
            else: output=decode_outputs(config,pending[0]['pending_values'])
            if output!=expected: raise ProtocolError(f'native/oracle disagreement: {workspace}')
            if case.startswith('nonboolean') or case in ('equivocate','tamper-triple','public-equivocate','public-highbit','noncanonical-wire','nonzero-padding','replayed-round'):
                raise ProtocolError('malformed registration accepted')
        native_log=(actors['P0']/'native.log').read_text()
        match=re.search(r'Global data sent = ([0-9.]+) MB',native_log)
        result={'case':case,'passed':True,'scope':'synthetic local native MPC; no Flower/BFT or joint-collusion proof',
                'runtime':'MP-SPDZ 0.4.3 '+('Rep4 active ring/binary' if backend=='rep4' else 'MASCOT active prime/binary')+', live execution',
                'backend':backend,'coordinate_circuit':coordinate_circuit,'seed_encoding':seed_encoding,
                'output_mode':config['output_mode'],'ring_bits':config['ring_bits'],
                'rep4_input_mode':config['rep4_input_mode'],
                'seed_input_values_per_client':2 if seed_encoding=='packed64' else 128,
                'parties':4,'clients':4,'dimension':dimension,'word_bits':word_bits,
                'private_seed_inputs_per_client':1,'native_sessions':1,
                'rounds_executed':(1 if failed and case=='replayed-round' else
                                   0 if failed or case=='aes' else len(rounds)),
                'rounds':0 if case=='aes' else len(rounds),'output':output,
                'expected':None if failed else expected,
                'wire_modulus':policy.modulus,'application_bits':width,'field_bits':field.bit_length() if backend=='mascot' else None,
                'synthetic_wrap_events':wraps,'source_sha256':sources,'aes_circuit_sha256':CIRCUIT_SHA256,
                'aes_circuit_commit':CIRCUIT_COMMIT,'policy_hash':digest(config),
                'compile_seconds':round(compile_seconds,3),'native_seconds':round(time.monotonic()-started,3),
                'global_data_sent_mb':float(match.group(1)) if match else None,
                'malicious_aggregator_faults_injected':0,'workspace':str(workspace),
                'malicious_client_faults_injected':int(case.startswith('nonboolean') or case=='equivocate'),
                'public_input_faults_injected':int(case in ('public-equivocate','public-highbit','noncanonical-wire','nonzero-padding','replayed-round')),
                'external_frame_tampering_injected':int(case=='tamper-triple'),
                'harness_sha256':harness_hashes}
        if chunked:
            result.update(chunk_blocks=chunk_blocks,runtime_public_input=True,
                          compiled_workspace_reused=str(reused) if reused else None,
                          compiled_artifact_hash=artifact_hash,compile_invocations=int(reused is None))
        if communication_stats and not failed:
            result['external_client_communication'] = [
                json.loads((actors[f'C{i}']/'communication.json').read_text()) for i in range(4)]
            result['communication_measurement'] = 'native -v plus ExternalIO message/framing counters; excludes TLS/TCP overhead'
        if profile_stages:
            result['stage_timers'] = {'1':'seed registration and Boolean validation/A2B',
                                     '2':'AES binary circuit', '3':'mask binary-to-arithmetic conversion',
                                     '4':'modular removal and coordinate range check',
                                     '5':'squared norm, threshold, conditional sum',
                                     '6':'minimum count and output release'}
            result['stage_timer_caveat'] = 'timer barriers change batching; on-demand preprocessing is charged where generated'
        (workspace/'result.json').write_text(json.dumps(result,indent=2))
        return result
    finally:
        for p in processes:
            if p.poll() is None:
                try: os.killpg(p.pid,signal.SIGTERM)
                except ProcessLookupError: pass
        for p in processes:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid,signal.SIGKILL); p.wait()
        for h in handles: h.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mp-spdz-dir',type=Path,required=True)
    parser.add_argument('--case',choices=['aes','multi-round','alternate','cross-chunk','edge-cases','nonboolean','nonboolean-high','equivocate','tamper-triple','public-equivocate','public-highbit','noncanonical-wire','nonzero-padding','replayed-round'],default='multi-round')
    parser.add_argument('--timeout',type=int,default=600)
    parser.add_argument('--dimension',type=int,default=2)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--communication-stats',action='store_true')
    parser.add_argument('--profile-stages',action='store_true')
    parser.add_argument('--backend',choices=['mascot','rep4'],default='mascot')
    parser.add_argument('--coordinate-circuit',choices=['arithmetic','binary','chunked'],default='arithmetic')
    parser.add_argument('--seed-encoding',choices=['bits','packed64'])
    parser.add_argument('--ring-bits',type=int,choices=[64,128],default=64)
    parser.add_argument('--word-bits',type=int,choices=[16,32],default=16)
    parser.add_argument('--native-public-output',action='store_true')
    parser.add_argument('--chunk-blocks',type=int,default=4)
    parser.add_argument('--compiled-workspace',type=Path)
    args=parser.parse_args()
    result=run_probe(args.mp_spdz_dir,args.case,args.timeout,args.dimension,args.communication_stats,args.profile_stages,
                     args.backend,args.coordinate_circuit,args.seed_encoding,args.ring_bits,args.word_bits,args.native_public_output,
                     args.chunk_blocks,args.compiled_workspace)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('x') as out: json.dump(result,out,indent=2)
    print(json.dumps(result,indent=2))


if __name__=='__main__': main()

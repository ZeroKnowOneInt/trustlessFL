"""Nine isolated roles on official Flower Deployment + native Rep4.

Host bootstrap is trusted; no host-administrator/kernel or shared-network
isolation claim. No raw audit. Only private-input native sockets use TLS in
this local fixture; Flower/RPC loopback is not a production transport setup.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

import tomli_w

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from trustlessfl.crypto import canonical,ProtocolError
from trustlessfl.seed_mpc_isolation import RoleSandbox
from trustlessfl.seed_mpc_session import load_deployment,rpc
from experiments.run_seed_mpc_flower import stage
from experiments.run_endpoint_flower import require_completed_run


def access_probes(output):
    roles=['server',*[f'C{i}' for i in range(4)],*[f'P{i}' for i in range(4)]]
    files={}
    for role in roles:
        home=RoleSandbox(output,role).home
        marker=home/'private-access-probe'; marker.write_bytes(os.urandom(32)); marker.chmod(0o600)
        files[role]=str(output/f'clients/{role}/client.json') if role.startswith('C') else (
            str(output/f'mpc/{role}/service-private.json') if role.startswith('P') else str(marker))
    records=[]
    script=('import json,sys,os; result={}; '
            '\nfor role,path in json.loads(sys.argv[1]).items():\n'
            ' try:\n  with open(path,"rb") as f: f.read(1)\n  result[role]=True\n'
            ' except OSError: result[role]=False\n'
            'print(json.dumps({"read":result,"pid":os.getpid(),"proc_parent_visible":os.path.exists("/proc/"+sys.argv[2])}))')
    for role in roles:
        sandbox=RoleSandbox(output,role)
        proc=subprocess.run(sandbox.command([sys.executable,'-c',script,json.dumps(files),str(os.getpid())]),
                            check=True,capture_output=True,text=True,timeout=30)
        result=json.loads(proc.stdout)
        if result['read']!={name:name==role for name in roles} or result['proc_parent_visible']:
            raise ProtocolError('cross-role file or host PID visible in namespace')
        records.append({'role':role,**result})
    report={'roles':9,'cross_role_denials':72,'own_file_readable':True,'host_parent_pid_hidden':True,
            'runtime':'bubblewrap filesystem + PID/user/ipc namespaces; shared loopback; trusted host bootstrap',
            'records':records}
    (output/'isolation-probes.json').write_bytes(canonical(report)); return report


def ports(count):
    sockets=[]
    try:
        for _ in range(count):
            sock=socket.socket(); sock.bind(('127.0.0.1',0)); sockets.append(sock)
        return [s.getsockname()[1] for s in sockets]
    finally:
        for sock in sockets: sock.close()


def run(output):
    output=output.resolve(); deployment,_=load_deployment(output/'deployment.json')
    if not deployment.get('role_isolation') or deployment.get('trusted_test_audit'):
        raise ProtocolError('isolated deployment requires role provisioning and disabled raw audit')
    access_probes(output)
    processes=[]; handles=[]; started=time.monotonic()
    def start(role,argv,cwd=None):
        sandbox=RoleSandbox(output,role); log=(sandbox.home/'runtime.log').open('x'); handles.append(log)
        process=subprocess.Popen(sandbox.command(argv,cwd=cwd),stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append(process); return process
    try:
        for i in range(4):
            start(f'P{i}',[sys.executable,'-m','trustlessfl.seed_mpc_service','--deployment',output/'deployment.json',
                          '--private',output/f'mpc/P{i}/service-private.json','--slot',str(i)])
        for i,url in enumerate(deployment['services']):
            end=time.monotonic()+40
            while True:
                if processes[i].poll() is not None: raise ProtocolError('isolated aggregator startup failed')
                try: rpc(url,'head',timeout=1); break
                except ProtocolError:
                    if time.monotonic()>end: raise ProtocolError('isolated aggregator readiness timeout')
                    time.sleep(.05)
        control,fleet,runtime,*node_ports=ports(7)
        server=RoleSandbox(output,'server'); flower_home=server.home/'flower-home'; flower_home.mkdir(exist_ok=True)
        (flower_home/'config.toml').write_text(tomli_w.dumps({'superlink':{'default':'isolated-local',
            'isolated-local':{'address':f'127.0.0.1:{control}','insecure':True}}}))
        start('server',[ROOT/'.venv/bin/flower-superlink','--insecure','--isolation','subprocess',
            '--disable-runtime-dependency-installation','--control-api-address',f'127.0.0.1:{control}',
            '--fleet-api-address',f'127.0.0.1:{fleet}','--host','127.0.0.1','--port',str(runtime)])
        for port in (control,fleet):
            end=time.monotonic()+40
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                except OSError:
                    if time.monotonic()>end: raise ProtocolError('isolated SuperLink readiness timeout')
                    time.sleep(.05)
        for i in range(4):
            start(f'C{i}',[ROOT/'.venv/bin/flower-supernode','--insecure','--superlink',f'127.0.0.1:{fleet}',
                '--node-config',f'partition-id={i} num-partitions=4','--host','127.0.0.1','--port',str(node_ports[i])])
        for port in node_ports:
            end=time.monotonic()+40
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                except OSError:
                    if time.monotonic()>end: raise ProtocolError('isolated SuperNode readiness timeout')
                    time.sleep(.05)
        time.sleep(.5)
        # CLI shares only the coordinator role namespace, never client files.
        log=(server.home/'cli.log').open('x'); handles.append(log)
        subprocess.run(server.command([ROOT/'.venv/bin/flwr','run',output/'app','isolated-local','--stream'],cwd=output/'app'),
                       stdout=log,stderr=subprocess.STDOUT,check=True,timeout=240)
        status=subprocess.run(server.command([ROOT/'.venv/bin/flwr','list','--format','json']),
                              capture_output=True,text=True,check=True,timeout=30)
        body=json.loads(status.stdout); require_completed_run(body)
        (output/'flower-run-status.json').write_bytes(canonical(body))
        if any((output/f'clients/C{i}/audit').exists() for i in range(4)):
            raise ProtocolError('raw client audit unexpectedly generated')
        print('ISOLATED_FLOWER_COMPLETED',flush=True)
    finally:
        # Signal each service inside the sandbox before terminating its init.
        # Killing bubblewrap first destroys the PID namespace before Python's
        # finally block can flush the endpoint meter and close its ledger.
        for i in range(4):
            expected=str(output/f'mpc/P{i}/service-private.json').encode()
            for entry in Path('/proc').iterdir():
                if not entry.name.isdigit(): continue
                try:
                    if not (entry/'comm').read_text().startswith('python'): continue
                    args=(entry/'cmdline').read_bytes().split(b'\0')
                    if b'trustlessfl.seed_mpc_service' in args and expected in args:
                        os.kill(int(entry.name),signal.SIGTERM)
                except (OSError,ProcessLookupError): pass
        deadline=time.monotonic()+5
        while any(p.poll() is None for p in processes[:4]) and time.monotonic()<deadline:
            time.sleep(.05)
        for process in processes:
            if process.poll() is None: os.killpg(process.pid,signal.SIGTERM)
        for process in processes:
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); process.wait()
        for handle in handles: handle.close()
        (output/'runtime-wall.json').write_bytes(canonical({'scope':'isolated deployment startup + Flower run + owned-process cleanup',
                                                         'seconds':time.monotonic()-started}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--phase',choices=['all','run'],default='all')
    parser.add_argument('--mp-spdz-dir',type=Path,default=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-telemetry')
    parser.add_argument('--component-input',choices=['stock-private-v1','holder-checked-direct-v1'],default='stock-private-v1')
    parser.add_argument('--chunk-blocks',type=int)
    args=parser.parse_args(); output=args.output.resolve()
    if args.phase=='all': stage(output,args.mp_spdz_dir,mode='fixture',dimension=65,
        rounds=3,snapshot_version=2,communication_meter=True,test_audit=False,role_isolation=True,component_input=args.component_input,chunk_blocks=args.chunk_blocks)
    run(output)

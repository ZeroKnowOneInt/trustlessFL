"""One local aggregator: own signing key, ledger, FIFO and native process.

Local functional deployment only. No remote log/checked flag is an RPC input.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import time

from .crypto import Identity, ProtocolError, canonical, digest
from .seed_mpc_committee import AggregatorGuard, digest_words
from .seed_mpc_native import NativeCheckpointReader
from .seed_mpc_session import load_deployment
from .seed_mpc_resources import read_resources


def pipe_write(fd,values,timeout):
    data=('\n'.join(map(str,values))+'\n').encode(); deadline=time.monotonic()+timeout
    while data:
        remaining=deadline-time.monotonic()
        if remaining<=0: raise ProtocolError('native pipe timeout')
        if not select.select([], [fd], [], min(remaining,.2))[1]: continue
        try:
            sent=os.write(fd,data); data=data[sent:]
        except BlockingIOError: continue


class LocalAggregator:
    def __init__(self,deployment_file,private_file,slot):
        self.deployment,self.committee=load_deployment(deployment_file)
        self.slot=slot; d=self.deployment
        private=json.loads(Path(private_file).read_text())
        if hashlib.sha256(Path(deployment_file).read_bytes()).hexdigest()!=private['deployment_sha256']:
            raise ProtocolError('aggregator deployment changed')
        self.actor=Path(private['actor']); self.actor.mkdir(exist_ok=True)
        identity=Identity.from_private(private['identity'])
        if identity.name!=self.committee.aggregators[slot]: raise ProtocolError('service slot differs')
        workspace=Path(d['workspace']); binary=Path(d['native_binary'])
        if (hashlib.sha256((workspace/'Programs/Circuits/aes_128.txt').read_bytes()).hexdigest()!=d['aes_sha256']
                or hashlib.sha256((workspace/'policy.json').read_bytes()).hexdigest()!=d['config_sha256']):
            raise ProtocolError('native circuit/config changed')
        if hashlib.sha256(binary.read_bytes()).hexdigest()!=d['binary_sha256']:
            raise ProtocolError('native binary changed')
        for relative,expected in d['artifacts'].items():
            if hashlib.sha256((workspace/'Programs'/relative).read_bytes()).hexdigest()!=expected:
                raise ProtocolError('compiled artifact changed')
        self.guard=AggregatorGuard(self.committee,identity,self.actor/'rounds.sqlite',d['initial_model'],create=True)
        self.program=d['program']; programs=self.actor/'Programs'
        programs.unlink(); programs.mkdir()
        for folder in ['Bytecode','Schedules','Circuits']:
            (programs/folder).symlink_to(workspace/'Programs'/folder,target_is_directory=True)
        public=programs/'Public-Input'; public.mkdir(); fifo=public/self.program; os.mkfifo(fifo,0o600)
        self.fd=os.open(fifo,os.O_RDWR|os.O_NONBLOCK)
        self.log=(self.actor/'native.log').open('x')
        self.started=time.monotonic()
        self.process=subprocess.Popen(['/usr/bin/time','-v','-o',str(self.actor/'native-resource.txt'),
            str(binary),'-pn',str(d['party_port']),'-h','127.0.0.1',
            '-R','64','-p',str(slot),self.program,'-OF','.','-v'],cwd=self.actor,
            stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
        self.reader=NativeCheckpointReader(self.guard,self.process,self.actor/'native.log')
        tags=[v for packet in self.committee.registrations for v in digest_words(digest(packet['body']))]
        pipe_write(self.fd,tags,d['timeout'])

    def action(self,action,body):
        if action=='head': return self.guard.head()
        if action=='ready':
            if not self.reader.registration_checked: self.reader.wait_registration(self.deployment['timeout'])
            return {'registration_checked':True,'aggregator':self.guard.identity.name}
        if not self.reader.registration_checked: raise ProtocolError('registration not checked')
        if action=='prepare': return self.guard.prepare(body['manifest'])
        if action=='execute':
            manifest=body['manifest']; self.guard.reserve(manifest,body['input_certificate'])
            pipe_write(self.fd,self.committee.runtime_round(manifest),self.deployment['timeout'])
            return self.reader.vote(manifest,self.deployment['timeout'])
        if action=='decide': return self.guard.accept(body['manifest'],body['result_certificate'])
        if action=='finish':
            if self.guard.head()['round']!=self.deployment['rounds']: raise ProtocolError('incomplete session')
            if self.process.wait(timeout=30)!=0: raise ProtocolError('native exit failed')
            text=(self.actor/'native.log').read_text()
            sent=re.search(r'Global data sent = ([0-9.]+) MB',text)
            return {'head':self.guard.head(),'native_exit':0,'internal_mb':float(sent[1]) if sent else None,
                    'resources':read_resources(self.actor/'native-resource.txt'),
                    'session_wall_seconds':round(time.monotonic()-self.started,3)}
        raise ProtocolError('unknown aggregator action')

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid,signal.SIGTERM)
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired: os.killpg(self.process.pid,signal.SIGKILL); self.process.wait()
        os.close(self.fd); self.log.close(); self.guard.ledger.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment',type=Path,required=True)
    parser.add_argument('--private',type=Path,required=True)
    parser.add_argument('--slot',type=int,choices=range(4),required=True)
    args=parser.parse_args(); owner=LocalAggregator(args.deployment,args.private,args.slot)
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length=int(self.headers.get('Content-Length',0))
                if not 0<length<=16*1024*1024: raise ProtocolError('invalid request size')
                body=json.loads(self.rfile.read(length)); result=owner.action(self.path.lstrip('/'),body)
                data=canonical({'result':result}); self.send_response(200)
            except Exception:
                # Do not echo client inputs, keys, pending outputs or exception values.
                data=canonical({'error':'protocol rejected'}); self.send_response(409)
            self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data)))
            self.end_headers(); self.wfile.write(data)
        def log_message(self,*args): pass
    port=int(owner.deployment['services'][args.slot].rsplit(':',1)[1])
    server=HTTPServer(('127.0.0.1',port),Handler)
    def stop(*_): raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop)
    try: server.serve_forever(poll_interval=.1)
    except KeyboardInterrupt: pass
    finally: server.server_close(); owner.close()


if __name__=='__main__': main()

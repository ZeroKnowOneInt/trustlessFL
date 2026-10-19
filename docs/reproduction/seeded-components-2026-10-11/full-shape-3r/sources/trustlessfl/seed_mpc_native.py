"""Locally owned native checkpoint observer. Not a peer attestation parser.

Only use with the pinned process launched by the aggregator's trusted adapter.
Never accept a peer-supplied log, path, or completed/checked Boolean as evidence.
"""
import re
import time
from collections import deque

from .crypto import ProtocolError, digest


class NativeCheckpointReader:
    def __init__(self,guard,process,log_path):
        self.guard=guard; self.process=process; self.log_path=log_path
        self.offset=0; self.registration_checked=False
        self.lines=deque()

    def _line(self,deadline):
        while time.monotonic()<deadline:
            if self.lines: return self.lines.popleft()
            with self.log_path.open() as stream:
                stream.seek(self.offset)
                for _ in range(256):
                    line=stream.readline()
                    if not line.endswith('\n'): break
                    self.offset=stream.tell(); self.lines.append(line.rstrip('\n'))
                if self.lines: return self.lines.popleft()
            if self.process.poll() is not None:
                raise ProtocolError('native ended before required checkpoint')
            time.sleep(.02)
        raise ProtocolError('native checkpoint timeout')

    def wait_registration(self,timeout=60):
        deadline=time.monotonic()+timeout
        while True:
            line=self._line(deadline)
            if line=='SEED_MPC_REG_CHECKED':
                self.registration_checked=True; return
            if line.startswith('SEED_MPC_PUBLIC ') or line.startswith('SEED_MPC_CHECKED '):
                raise ProtocolError('result before checked registration')

    def vote(self,manifest,timeout=60):
        if not self.registration_checked: raise ProtocolError('registration not checked')
        committee=self.guard.committee
        context=committee.check_manifest(manifest)
        row=self.guard.ledger.row(context.round_id)
        if not row or row['phase']!='running' or row['input_hash']!=digest(manifest):
            raise ProtocolError('checkpoint input not reserved')
        pending=[]; deadline=time.monotonic()+timeout
        while True:
            line=self._line(deadline)
            value=re.fullmatch(r'SEED_MPC_PUBLIC (-?\d+)',line)
            if value:
                pending.append(int(value[1]))
                if len(pending)>committee.policy.dimension+2: raise ProtocolError('excess pending output')
            elif line.startswith('SEED_MPC_CHECKED '):
                match=re.fullmatch(r'SEED_MPC_CHECKED (\d+) (-?\d+) (-?\d+) (-?\d+) (-?\d+)',line)
                if not match or int(match[1])!=context.round_id: raise ProtocolError('checkpoint round differs')
                words=[int(match[j]) for j in range(2,6)]
                if any(not -(1<<63)<=v<(1<<64) for v in words): raise ProtocolError('invalid checkpoint digest word')
                bound=b''.join((v%(1<<64)).to_bytes(8,'big') for v in words).hex()
                if bound!=digest(manifest): raise ProtocolError('checkpoint input digest differs')
                if len(pending)!=committee.policy.dimension+2: raise ProtocolError('incomplete pending result')
                ok,count,*total=pending
                if ok==0:
                    if count or any(total): raise ProtocolError('abort revealed pending SUM/count')
                    result={'status':'abort'}
                elif ok==1: result={'status':'ok','count':count,'sum':total}
                else: raise ProtocolError('invalid pending status')
                return self.guard._postchecked_vote(manifest,result)

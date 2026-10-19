"""Public Flower streaming and best-effort notifications for v2 sessions."""
import json
import time
import secrets
from concurrent.futures import ThreadPoolExecutor, wait

from flwr.app import Message

from .crypto import ProtocolError,canonical,digest,verify


def with_progress(operation,progress,interval=.05):
    """Join the RPC before returning; only the caller thread accesses Flower Grid."""
    if progress is None: return operation()
    with ThreadPoolExecutor(max_workers=1) as executor:
        future=executor.submit(operation)
        while not wait([future],timeout=interval).done:
            progress()
        progress()
        return future.result()


def chain_messages(records,model,targets,confirmed,*,kind,ttl,round_id=None):
    """Reuse identical public content within a dispatch; do not omit any proof.

    A large roster must not allocate N copies of the same ND-sized suffix.
    Metadata remains recipient-specific; content is never mutated after dispatch.
    """
    from flwr.app import ArrayRecord,ConfigRecord,RecordDict
    import numpy as np
    content_by_cursor={}
    for node,client in targets.items():
        cursor=confirmed[client]
        if cursor not in content_by_cursor:
            chain={'json':canonical(records[cursor:]).decode()}
            if kind=='query.commit': chain['round']=round_id
            content=RecordDict({'model':ArrayRecord([np.asarray(model,dtype=np.float64)]),'chain':ConfigRecord(chain)})
            if kind=='train': content['config']=ConfigRecord({'round':round_id})
            content_by_cursor[cursor]=content
        yield Message(content_by_cursor[cursor],dst_node_id=node,message_type=kind,ttl=ttl)


def stream_replies(grid,messages,timeout,*,clock=time.monotonic,sleep=time.sleep,discover=None,progress=None):
    """Yield replies immediately, never defer receipts until the last client."""
    messages=list(messages); pending=set(grid.push_messages(messages))
    if len(pending)!=len(messages): raise ProtocolError('Flower dispatch incomplete')
    deadline=clock()+timeout
    while (pending or discover is not None) and clock()<deadline:
        if progress is not None: progress()
        if discover is not None:
            extra=discover()
            if extra is None: return
            if extra:
                added=list(grid.push_messages(extra))
                if len(added)!=len(extra) or pending.intersection(added): raise ProtocolError('dynamic Flower dispatch incomplete')
                pending.update(added)
        replies=list(grid.pull_messages(pending))
        for reply in replies:
            message_id=reply.metadata.reply_to_message_id
            if message_id not in pending: raise ProtocolError('duplicate/unrequested Flower reply')
            pending.remove(message_id)
            # Processing a previous reply (including durable receipts) may take time.
            if clock()<deadline: yield reply
        if pending or discover is not None: sleep(min(.02,max(0,deadline-clock())))


class CommitNotifications:
    """No ACK is a precondition to applying results or starting the next round."""
    def __init__(self,grid,committee,mapping,*,ttl=60.,clock=time.monotonic):
        self.grid=grid; self.committee=committee; self.mapping=mapping
        self.confirmed={client:0 for client in mapping.values()}; self.pending={}
        self.events=[]
        self.ttl=ttl; self.clock=clock; self.known={}; self.failed=set(); self.last_query={}

    def poll(self):
        if not self.pending: return
        for reply in self.grid.pull_messages(list(self.pending)):
            request_id=reply.metadata.reply_to_message_id
            expected=self.pending.pop(request_id,None)
            if expected is None: raise ProtocolError('unrequested commit reply')
            node,client,head,nonce,_=expected; status='invalid'
            try:
                if reply.metadata.src_node_id!=node or reply.has_error(): raise ProtocolError('failed commit delivery')
                if set(reply.content)!= {'ack'} or set(reply.content['ack'])!= {'envelope'}:
                    raise ProtocolError('invalid commit acknowledgment')
                body=verify(json.loads(reply.content['ack']['envelope']),self.committee.registry,sender=client)
                if not isinstance(body,dict): raise ProtocolError('invalid client head body')
                r=body.get('round_id')
                if type(r) is not int or r not in self.known or (nonce is None and r<head['round']):
                    raise ProtocolError('unknown/stale client head')
                known=self.known[r]
                expected_body={'protocol':'seed-mpc-client-head-v2','session_id':self.committee.session_id,
                    'round_id':r,'decision':known['decision'],'model_hash':known['model_hash']}
                if nonce is not None:
                    expected_body.update(protocol='seed-mpc-client-head-proof-v1',node_id=node,nonce=nonce)
                if canonical(body)!=canonical(expected_body): raise ProtocolError('commit acknowledgment differs')
                self.confirmed[client]=max(self.confirmed[client],r); status='confirmed'
                self.failed.discard(client)
            except (ProtocolError,KeyError,TypeError,ValueError):
                # A malformed/missing ACK affects delivery knowledge, never the certified model.
                status='missing' if reply.has_error() else 'invalid'
                self.failed.add(client)
            event={'client_id':client,'round':head['round'],'status':status,'kind':'head-query' if nonce else 'commit'}
            if reply.has_error() and hasattr(reply,'error'): event['error_code']=reply.error.code
            self.events.append(event)

    def recover(self):
        """Best-effort fresh head proof, never a quorum/round completion barrier."""
        from flwr.app import ConfigRecord,RecordDict
        if not self.known: return
        latest=max(self.known); now=self.clock()
        for node,client in list(self.mapping.items()):
            if self.confirmed[client]>=latest: continue
            pending=[p for p in self.pending.values() if p[1]==client]
            if any(p[3] is not None for p in pending): continue
            if client not in self.failed and not any(now-p[4]>=5 for p in pending): continue
            if now-self.last_query.get(client,float('-inf'))<2: continue
            nonce=secrets.token_hex(32)
            message=Message(RecordDict({'challenge':ConfigRecord({'session_id':self.committee.session_id,'nonce':nonce})}),
                dst_node_id=node,message_type='query.head',ttl=self.ttl)
            ids=list(self.grid.push_messages([message]))
            if len(ids)!=1 or ids[0] in self.pending: raise ProtocolError('Flower head query dispatch incomplete')
            self.pending[ids[0]]=(node,client,{'round':latest},nonce,now); self.last_query[client]=now

    def send(self,records,head):
        targets=dict(self.mapping); metadata=[]
        for record in records:
            body=record['result_certificate']['body']; r=body['round_id']
            self.known[r]={'decision':digest(body),'model_hash':body['next_model_hash']}
        if records:
            first=records[0]['manifest']
            self.known[0]={'decision':first['parent_decision'],'model_hash':first['context']['model_hash']}
        messages=list(chain_messages(records,head['model'],targets,self.confirmed,kind='query.commit',
                                     ttl=self.ttl,round_id=head['round']))
        for node,client in targets.items():
            metadata.append((node,client,{'round':head['round']},None,self.clock()))
        ids=list(self.grid.push_messages(messages))
        if len(ids)!=len(messages) or len(set(ids))!=len(ids): raise ProtocolError('Flower commit dispatch incomplete')
        for message_id,expected in zip(ids,metadata,strict=True): self.pending[message_id]=expected


def synchronize(state,decisions,model,target_round):
    """Validate the whole suffix before durable writes; retries verify old rows.

    A delayed certified commit may target an older already stored head. It never
    rolls the client back. Training separately requires the exact next round.
    """
    import numpy as np
    if (not isinstance(decisions,list) or type(target_round) is not int or target_round<0
            or model.dtype!=np.float64 or model.shape!=(state.committee.policy.dimension,)
            or not np.isfinite(model).all()): raise ProtocolError('invalid synchronization target')
    committee=state.committee; initial=state.head(); simulated=dict(initial); previous=None
    for decision in decisions:
        if not isinstance(decision,dict) or set(decision)!= {'manifest','input_certificate','result_certificate'}:
            raise ProtocolError('malformed synchronization decision')
        manifest=decision['manifest']; context=committee.check_manifest(manifest); r=context.round_id
        if r>target_round or (previous is not None and r!=previous+1): raise ProtocolError('synchronization chain gap')
        previous=r
        committee.check_certificate(decision['input_certificate'],committee.input_body(manifest))
        if r<=initial['round']:
            row=state.ledger.row(r)
            if not row or row['phase']!='decided' or row['input_hash']!=digest(manifest):
                raise ProtocolError('conflicting synchronization replay')
            expected=json.loads(row['result_body'])
        else:
            if r!=simulated['round']+1 or manifest['parent_decision']!=simulated['decision']:
                raise ProtocolError('synchronization parent/round differs')
            result=committee.certificate_result(decision['result_certificate'])
            expected=committee.result_body(manifest,result,simulated['model'])
            simulated={'round':r,'decision':digest(expected),'model':committee.next_model(simulated['model'],result)}
        committee.check_certificate(decision['result_certificate'],expected)
    if simulated['round']<target_round: raise ProtocolError('incomplete synchronization chain')
    if target_round<initial['round']:
        if target_round==0: expected_hash=committee.contract['initial_model_hash']
        else:
            row=state.ledger.row(target_round)
            if not row or row['phase']!='decided': raise ProtocolError('missing old synchronization head')
            expected_hash=json.loads(row['result_body'])['next_model_hash']
    else: expected_hash=digest(simulated['model'])
    if digest(model.tolist())!=expected_hash: raise ProtocolError('synchronization model differs')
    applied=0
    for decision in decisions:
        applied+=int(state.apply(decision['manifest'],decision['input_certificate'],decision['result_certificate']))
    return applied

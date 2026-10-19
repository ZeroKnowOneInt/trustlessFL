"""Public Flower streaming and best-effort notifications for v2 sessions."""
import json
import time

from flwr.app import Message

from .crypto import ProtocolError,canonical,digest,verify


def stream_replies(grid,messages,timeout,*,clock=time.monotonic,sleep=time.sleep):
    """Yield replies immediately, never defer receipts until the last client."""
    messages=list(messages); pending=set(grid.push_messages(messages))
    if len(pending)!=len(messages): raise ProtocolError('Flower dispatch incomplete')
    deadline=clock()+timeout
    while pending and clock()<deadline:
        replies=list(grid.pull_messages(pending))
        for reply in replies:
            message_id=reply.metadata.reply_to_message_id
            if message_id not in pending: raise ProtocolError('duplicate/unrequested Flower reply')
            pending.remove(message_id)
            # Processing a previous reply (including durable receipts) may take time.
            if clock()<deadline: yield reply
        if pending: sleep(min(.02,max(0,deadline-clock())))


class CommitNotifications:
    """No ACK is a precondition to applying results or starting the next round."""
    def __init__(self,grid,committee,mapping):
        self.grid=grid; self.committee=committee; self.mapping=mapping
        self.confirmed={client:0 for client in mapping.values()}; self.pending={}
        self.events=[]

    def poll(self):
        if not self.pending: return
        for reply in self.grid.pull_messages(list(self.pending)):
            request_id=reply.metadata.reply_to_message_id
            expected=self.pending.pop(request_id,None)
            if expected is None: raise ProtocolError('unrequested commit reply')
            node,head=expected; client=self.mapping[node]; status='invalid'
            try:
                if reply.metadata.src_node_id!=node or reply.has_error(): raise ProtocolError('failed commit delivery')
                if set(reply.content)!= {'ack'} or set(reply.content['ack'])!= {'envelope'}:
                    raise ProtocolError('invalid commit acknowledgment')
                body=verify(json.loads(reply.content['ack']['envelope']),self.committee.registry,sender=client)
                expected_body={'protocol':'seed-mpc-client-head-v2','session_id':self.committee.session_id,
                    'round_id':head['round'],'decision':head['decision'],'model_hash':digest(head['model'])}
                if canonical(body)!=canonical(expected_body): raise ProtocolError('commit acknowledgment differs')
                self.confirmed[client]=max(self.confirmed[client],head['round']); status='confirmed'
            except (ProtocolError,KeyError,TypeError,ValueError):
                # A malformed/missing ACK affects delivery knowledge, never the certified model.
                status='missing' if reply.has_error() else 'invalid'
            self.events.append({'client_id':client,'round':head['round'],'status':status})

    def send(self,records,head):
        from flwr.app import ArrayRecord,ConfigRecord,RecordDict
        import numpy as np
        messages=[]; metadata=[]
        for node,client in self.mapping.items():
            suffix=records[self.confirmed[client]:]
            content=RecordDict({'chain':ConfigRecord({'json':canonical(suffix).decode(),'round':head['round']}),
                                'model':ArrayRecord([np.asarray(head['model'],dtype=np.float64)])})
            messages.append(Message(content,dst_node_id=node,message_type='query.commit',ttl=60.0))
            metadata.append((node,head))
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

"""Signed input snapshots, durable quorum locks, and post-check results.

Fixed four-party/one-fault safety layer. No pacemaker or view-change liveness.
The native checkpoint adapter must be owned locally, never fed by a peer RPC.
"""
from dataclasses import asdict
from copy import deepcopy
import math
import re

from .crypto import ProtocolError, canonical, digest, verify
from .seed_mpc_wire import RoundContext
from .seed_mpc_ledger import SeedLedger


def require_hash(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None:
        raise ProtocolError('invalid digest')
    return value


def digest_words(value):
    raw=bytes.fromhex(require_hash(value))
    return [int.from_bytes(raw[j:j+8],'big') for j in range(0,32,8)]


def same_transcript(left,right):
    # Python equality aliases True/1 and 1.0/1; signed canonical bytes do not.
    try: return canonical(left)==canonical(right)
    except (ValueError,TypeError) as exc: raise ProtocolError('noncanonical transcript') from exc


class SeedCommittee:
    def __init__(self,policy,session_id,epoch,clients,aggregators,registry,registrations,execution_hash,initial_model):
        policy.validate_ring(64)
        if (len(clients)!=policy.max_clients or len(aggregators)!=4 or len(set(clients))!=len(clients)
                or len(set(aggregators))!=4 or set(clients)&set(aggregators)):
            raise ProtocolError('invalid fixed committee/roster')
        if any(name not in registry for name in [*clients,*aggregators]): raise ProtocolError('unpinned identity')
        if len({registry[name]['signing'] for name in aggregators})!=4: raise ProtocolError('duplicate committee signing keys')
        registry=deepcopy(registry); registrations=deepcopy(registrations)
        self.policy=policy; self.clients=tuple(clients); self.aggregators=tuple(aggregators); self.registry=registry
        self.execution_hash=require_hash(execution_hash)
        self.session_id=session_id; self.epoch=epoch
        # Reuse existing context validation; the native counter currently has 63 bits.
        RoundContext(session_id,epoch,1,digest(initial_model),policy.policy_hash)
        self.validate_model(initial_model)
        if len(registrations)!=len(clients): raise ProtocolError('missing registration')
        self.registrations=tuple(registrations)
        handles=[]
        for slot,(name,envelope) in enumerate(zip(clients,registrations,strict=True)):
            body=verify(envelope,registry,sender=name)
            handle=body.get('key_handle') if isinstance(body,dict) else None
            if type(handle) is not str or not 1<=len(handle)<=128: raise ProtocolError('invalid key handle')
            expected={'protocol':'seed-mpc-registration-v1','session_id':session_id,'committee_epoch':epoch,
                      'client_id':name,'slot':slot,'key_handle':handle,'policy_hash':policy.policy_hash,
                      'execution_hash':execution_hash}
            if not same_transcript(body,expected): raise ProtocolError('registration context differs')
            handles.append(handle)
        if len(set(handles))!=len(handles): raise ProtocolError('duplicate registration handle')
        self.handles=tuple(handles)
        self.contract={'protocol':'seed-mpc-committee-v1','session_id':session_id,'committee_epoch':epoch,
                       'policy':asdict(policy),'execution_hash':execution_hash,'clients':list(clients),
                       'aggregators':list(aggregators),'registry_hash':digest(registry),
                       'registrations':list(registrations),'initial_model_hash':digest(initial_model)}

    def validate_model(self,model):
        if not isinstance(model,list) or len(model)!=self.policy.dimension or any(
                type(v) is not float or not math.isfinite(v) for v in model):
            raise ProtocolError('noncanonical public float64 model')

    def validate_initial_model(self,model):
        self.validate_model(model)
        if digest(model)!=self.contract['initial_model_hash']:
            raise ProtocolError('initial model differs from committee contract')

    def manifest(self,context,parent,envelopes):
        require_hash(parent)
        if (context.session_id!=self.session_id or context.committee_epoch!=self.epoch
                or context.policy_hash!=self.policy.policy_hash or context.round_id>=2**63):
            raise ProtocolError('input session/policy/counter differs')
        if not isinstance(envelopes,list): raise ProtocolError('invalid signed input list')
        rows={name:[] for name in self.clients}; ordered=[]
        for envelope in envelopes:
            body=verify(envelope,self.registry)
            if not isinstance(body,dict) or body.get('client_id') not in rows: raise ProtocolError('unregistered input')
            name=body['client_id']; slot=self.clients.index(name)
            if envelope['sender']!=name: raise ProtocolError('input sender differs')
            values=body.get('values'); offset=body.get('offset')
            if not isinstance(values,list): raise ProtocolError('invalid signed wire')
            expected=context.payload(self.policy,client_id=name,key_handle=self.handles[slot],values=values,offset=offset)
            if not same_transcript(body,expected): raise ProtocolError('signed input context/handle differs')
            rows[name].append((offset,envelope))
        for name in self.clients:
            position=0
            for offset,envelope in sorted(rows[name],key=lambda pair:pair[0]):
                if offset!=position: raise ProtocolError('missing, duplicated or overlapping input chunk')
                position+=len(envelope['body']['values']); ordered.append(deepcopy(envelope))
            if position!=self.policy.dimension: raise ProtocolError('incomplete client wire')
        return {'protocol':'seed-mpc-input-snapshot-v1','context':asdict(context),
                'parent_decision':parent,'contract_hash':digest(self.contract),'inputs':ordered}

    def check_manifest(self,manifest):
        try:
            context=RoundContext(**manifest['context'])
            expected=self.manifest(context,manifest['parent_decision'],manifest['inputs'])
            if not same_transcript(expected,manifest): raise ProtocolError('noncanonical input snapshot')
            return context
        except (KeyError,TypeError) as exc: raise ProtocolError('malformed input snapshot') from exc

    def input_body(self,manifest):
        context=self.check_manifest(manifest)
        return {'protocol':'seed-mpc-input-vote-v1','contract_hash':digest(self.contract),
                'round_id':context.round_id,'input_hash':digest(manifest)}

    def certificate(self,body,votes):
        if not isinstance(votes,list): raise ProtocolError('invalid certificate votes')
        unique={}
        for envelope in votes:
            name=envelope.get('sender') if isinstance(envelope,dict) else None
            if name not in self.aggregators or name in unique: raise ProtocolError('duplicate or noncommittee vote')
            if not same_transcript(verify(envelope,self.registry,sender=name),body): raise ProtocolError('vote body differs')
            unique[name]=envelope
        if len(unique)<3: raise ProtocolError('three distinct signatures required')
        return deepcopy({'body':body,'votes':[unique[name] for name in sorted(unique)]})

    def check_certificate(self,certificate,expected):
        if not isinstance(certificate,dict) or set(certificate)!= {'body','votes'} or not same_transcript(certificate['body'],expected):
            raise ProtocolError('certificate context differs')
        self.certificate(expected,certificate['votes'])

    @staticmethod
    def certificate_result(certificate):
        if (not isinstance(certificate,dict) or set(certificate)!= {'body','votes'}
                or not isinstance(certificate['body'],dict) or 'result' not in certificate['body']):
            raise ProtocolError('malformed result certificate')
        return certificate['body']['result']

    def wire_rows(self,manifest):
        self.check_manifest(manifest)
        rows={name:[] for name in self.clients}
        for envelope in manifest['inputs']: rows[envelope['sender']].extend(envelope['body']['values'])
        return [rows[name] for name in self.clients]

    def runtime_round(self,manifest,chunk_blocks=4):
        context=self.check_manifest(manifest)
        chunk=chunk_blocks*(128//self.policy.word_bits)
        padded=((self.policy.dimension+chunk-1)//chunk)*chunk
        stream=[context.round_id,*digest_words(digest(manifest))]
        for row in self.wire_rows(manifest): stream.extend(row+[0]*(padded-len(row)))
        return stream

    def next_model(self,model,result):
        self.validate_model(model)
        if result=={'status':'abort'}: return list(model)
        if not isinstance(result,dict) or set(result)!= {'status','count','sum'} or result['status']!='ok':
            raise ProtocolError('invalid MPC result')
        count=result['count']; total=result['sum']
        if type(count) is not int or not self.policy.minimum_accepted<=count<=len(self.clients):
            raise ProtocolError('invalid result count')
        if not isinstance(total,list) or len(total)!=self.policy.dimension or any(
                type(v) is not int or abs(v)>count*self.policy.coordinate_cap for v in total):
            raise ProtocolError('invalid result SUM')
        next_model=[a+b/(self.policy.scale*count) for a,b in zip(model,total,strict=True)]
        self.validate_model(next_model)
        return next_model

    def result_body(self,manifest,result,model):
        context=self.check_manifest(manifest)
        if digest(model)!=context.model_hash: raise ProtocolError('result parent model differs')
        next_model=self.next_model(model,result)
        return {'protocol':'seed-mpc-result-vote-v1','contract_hash':digest(self.contract),
                'round_id':context.round_id,'input_hash':digest(manifest),'parent_decision':manifest['parent_decision'],
                'model_hash':context.model_hash,'next_model_hash':digest(next_model),'result':deepcopy(result)}


class AggregatorGuard:
    def __init__(self,committee,identity,path,initial_model,*,create=False):
        if identity.name not in committee.aggregators or identity.public()!=committee.registry[identity.name]:
            raise ProtocolError('aggregator identity not pinned')
        committee.validate_initial_model(initial_model)
        self.committee=committee; self.identity=identity
        self.ledger=SeedLedger(path,{'committee':committee.contract,'owner':identity.name},initial_model,create=create)
        # All owners use the same public genesis parent; local identity isn't part of it.
        self.genesis=digest({'genesis':committee.contract})

    def head(self):
        head=self.ledger.head()
        if head['round']==0: head['decision']=self.genesis
        return head

    def prepare(self,manifest):
        context=self.committee.check_manifest(manifest); head=self.head()
        if manifest['parent_decision']!=head['decision'] or context.model_hash!=digest(head['model']):
            raise ProtocolError('input parent/model differs from durable head')
        body=self.committee.input_body(manifest)
        return self.ledger.prepare(context.round_id,digest(manifest),manifest,self.identity.sign(body))

    def reserve(self,manifest,certificate):
        self.committee.check_certificate(certificate,self.committee.input_body(manifest))
        self.ledger.reserve(manifest['context']['round_id'],digest(manifest))

    def _postchecked_vote(self,manifest,result):
        # Local native adapter only: no network API accepts a "checked=True" flag.
        body=self.committee.result_body(manifest,result,self.head()['model'])
        return self.ledger.checked(body['round_id'],body['input_hash'],body,self.identity.sign(body))

    def accept(self,manifest,certificate):
        self.committee.check_manifest(manifest)
        row=self.ledger.row(manifest['context']['round_id'])
        if row and row['phase']=='decided':
            import json
            body=json.loads(row['result_body'])
            self.committee.check_certificate(certificate,body)
            if body['input_hash']!=digest(manifest): raise ProtocolError('replayed decision input differs')
            return False
        body=self.committee.result_body(manifest,self.committee.certificate_result(certificate),self.head()['model'])
        self.committee.check_certificate(certificate,body)
        model=self.committee.next_model(self.head()['model'],body['result'])
        return self.ledger.decide(body['round_id'],body['input_hash'],body,certificate,model)


class CoordinatorState:
    def __init__(self,committee,path,initial_model,*,create=False):
        committee.validate_initial_model(initial_model)
        self.committee=committee
        self.ledger=SeedLedger(path,committee.contract,initial_model,create=create)

    def head(self): return self.ledger.head()

    def apply(self,manifest,input_certificate,result_certificate):
        committee=self.committee; context=committee.check_manifest(manifest)
        committee.check_certificate(input_certificate,committee.input_body(manifest))
        row=self.ledger.row(context.round_id)
        if row and row['phase']=='decided':
            import json
            body=json.loads(row['result_body'])
            committee.check_certificate(result_certificate,body)
            if body['input_hash']!=digest(manifest): raise ProtocolError('replayed result input differs')
            return False
        head=self.head()
        if context.round_id!=head['round']+1 or manifest['parent_decision']!=head['decision']:
            raise ProtocolError('coordinator result parent/round differs')
        body=committee.result_body(manifest,committee.certificate_result(result_certificate),head['model'])
        committee.check_certificate(result_certificate,body)
        # Certificate verification precedes preparation and atomic model update.
        self.ledger.prepare(context.round_id,digest(manifest),manifest,input_certificate['votes'][0])
        model=committee.next_model(head['model'],body['result'])
        return self.ledger.decide(context.round_id,digest(manifest),body,result_certificate,model)

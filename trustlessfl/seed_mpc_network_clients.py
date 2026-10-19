"""Authenticate a registered logical client after Flower assigns a new node ID."""
import json
import secrets

from flwr.app import ConfigRecord,Message,RecordDict
from .crypto import ProtocolError,canonical,verify


def discover(grid,committee,mapping,*,timeout):
    known=set(mapping)
    live=list(grid.get_node_ids())
    changes=[]
    for node in live:
        if node in known: continue
        challenge=secrets.token_hex(32)
        content=RecordDict({'challenge':ConfigRecord({'nonce':challenge,'session_id':committee.session_id})})
        replies=list(grid.send_and_receive([Message(content,dst_node_id=node,message_type='query.identity')],timeout=timeout))
        if len(replies)!=1 or replies[0].has_error(): continue
        reply=replies[0]
        try:
            client=authenticated_identity(reply,committee,node,challenge)
        except (ProtocolError,KeyError,TypeError,ValueError): continue
        old=[n for n,c in mapping.items() if c==client]
        if any(n in live for n in old): continue
        for n in old: mapping.pop(n)
        mapping[node]=client; known.add(node)
        changes.append({'client_id':client,'old_nodes':old,'node':node})
    return changes


def authenticated_identity(reply,committee,node,nonce):
    if reply.metadata.src_node_id!=node or reply.has_error() or set(reply.content)!= {'registration'}:
        raise ProtocolError('invalid client discovery reply')
    record=reply.content['registration']; packet=json.loads(record['envelope']); client=packet['sender']
    if client not in committee.clients: raise ProtocolError('unregistered client node')
    slot=committee.clients.index(client)
    verify(packet,committee.registry,sender=client)
    if canonical(packet)!=canonical(committee.registrations[slot]): raise ProtocolError('client enrollment differs')
    proof=verify(json.loads(record['proof']),committee.registry,sender=client)
    expected={'protocol':'seed-mpc-node-binding-v1','session_id':committee.session_id,'client_id':client,
        'node_id':node,'nonce':nonce}
    if proof!=expected: raise ProtocolError('client node challenge differs')
    return client

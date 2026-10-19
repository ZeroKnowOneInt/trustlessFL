"""Probe adapter for Rep4 full replicated triple components.

Assumes the pinned backend mapping P_p holds components p+1,p+2,p+3.
Rejects disagreement rather than claiming guaranteed output delivery.
"""
from .crypto import ProtocolError


def reconstruct_replicated_triples(messages, count, ring_bits):
    if type(count) is not int or count < 1 or ring_bits not in (64, 128) or len(messages) != 4:
        raise ProtocolError('invalid Rep4 triple contract')
    size = ring_bits//8
    if any(not isinstance(body, bytes) or len(body) != count*9*size for body in messages):
        raise ProtocolError('invalid Rep4 triple message length')
    modulus = 1 << ring_bits
    triples = []
    for j in range(count):
        values = []
        for t in range(3):
            components = [[] for _ in range(4)]
            for party,body in enumerate(messages):
                for local in range(3):
                    offset = ((j*3+t)*3+local)*size
                    value = int.from_bytes(body[offset:offset+size], 'little')
                    components[(party+local+1)%4].append(value)
            if any(len(copies)!=3 or len(set(copies))!=1 for copies in components):
                raise ProtocolError('inconsistent replicated triple components')
            values.append(sum(copies[0] for copies in components)%modulus)
        if values[0]*values[1]%modulus != values[2]:
            raise ProtocolError('invalid replicated input triple')
        triples.append(values)
    return triples

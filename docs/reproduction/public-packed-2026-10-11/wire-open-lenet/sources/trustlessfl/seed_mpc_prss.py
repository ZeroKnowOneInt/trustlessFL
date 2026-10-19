"""Client-specific seeded mask components; local expansion, authenticated MPC input.

This adapter does not import unchecked native replicated shares. Each component
is privately input by all three holders and compared inside the active circuit.
"""
import hashlib
from pathlib import Path
from functools import reduce
from operator import xor
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from .crypto import ProtocolError, canonical, digest, encrypt_share, decrypt_share, verify
from .seed_mpc_wire import mask_words

MASK_MODE = 'rep4-seeded-components-v1'
LEGACY_MASK_MODE = 'secret-aes-v1'


def local_source_hashes():
    result={}
    for name in ('seed_mpc_prss.py','seed_mpc_wire.py'):
        with Path(__file__).with_name(name).open('rb') as stream:
            result[name]=hashlib.file_digest(stream,'sha256').hexdigest()
    return result


def require_mask_implementation(expected):
    if not isinstance(expected,dict) or expected != local_source_hashes():
        raise ProtocolError('local mask implementation differs from execution binding')


def held_components(party):
    if type(party) is not int or party not in range(4):
        raise ProtocolError('invalid component holder')
    return tuple((party + local + 1) % 4 for local in range(3))


def validate_seeds(seeds):
    if (not isinstance(seeds, (tuple, list)) or len(seeds) != 4
            or any(type(seed) is not bytes or len(seed) != 16 for seed in seeds)):
        raise ProtocolError('four independent 128-bit component seeds required')
    return tuple(seeds)


def component_words(seed, registration, component, round_id, dimension, word_bits=16, *, offset=0):
    if type(seed) is not bytes or len(seed) != 16 or type(component) is not int or component not in range(4):
        raise ProtocolError('invalid component seed')
    # The registration binds session, epoch, client, handle, policy and execution.
    namespace = bytes.fromhex(digest(registration))
    key = HKDF(algorithm=SHA256(), length=16, salt=namespace,
               info=b'trustlessfl/seeded-mask-component/v1/' + bytes([component])).derive(seed)
    return mask_words(key, round_id, dimension, word_bits, offset=offset)


def combined_mask(seeds, registration, round_id, dimension, word_bits=16, *, offset=0):
    streams = [component_words(seed, registration, j, round_id, dimension, word_bits, offset=offset)
               for j, seed in enumerate(validate_seeds(seeds))]
    return tuple(reduce(xor, column) for column in zip(*streams, strict=True))


def seed_packet(identity, seeds, registration, party, recipient_public):
    components = held_components(party)
    seeds = validate_seeds(seeds)
    aad = {'protocol': MASK_MODE, 'registration_digest': digest(registration),
           'sender': identity.name, 'recipient': f'A{party}', 'components': list(components)}
    packed = int.from_bytes(b''.join(seeds[j] for j in components), 'big')
    body = {**aad, 'encrypted': encrypt_share(packed, recipient_public['encryption'], aad)}
    return identity.sign(body)


def open_seed_packet(packet, identity, registry, registration, party):
    if identity.name != f'A{party}':
        raise ProtocolError('component recipient differs')
    body = verify(packet, registry, sender=registration['client_id'])
    components = held_components(party)
    aad = {'protocol': MASK_MODE, 'registration_digest': digest(registration),
           'sender': registration['client_id'], 'recipient': identity.name, 'components': list(components)}
    if not isinstance(body, dict) or set(body) != set(aad) | {'encrypted'} or any(body[k] != v for k, v in aad.items()):
        raise ProtocolError('component registration binding differs')
    packed = decrypt_share(body['encrypted'], identity, aad)
    if packed >= 1 << 384:
        raise ProtocolError('component packet exceeds three seeds')
    raw = packed.to_bytes(48, 'big')
    return {j: raw[16*k:16*(k+1)] for k, j in enumerate(components)}


def private_round_words(component_seeds, registrations, party, round_id, dimension, chunk_blocks, word_bits=16):
    """Exactly the compiler's input order; no complete mask in any party's view."""
    if (type(dimension) is not int or dimension < 1
            or len(component_seeds) != len(registrations) or word_bits not in (16, 32)):
        raise ProtocolError('invalid component input roster')
    if type(chunk_blocks) is not int or not 1 <= chunk_blocks <= 64:
        raise ProtocolError('invalid component input chunk')
    components = held_components(party)
    per_chunk = chunk_blocks * (128 // word_bits)
    padded = ((dimension + per_chunk - 1) // per_chunk) * per_chunk
    for seeds, registration in zip(component_seeds, registrations, strict=True):
        if set(seeds) != set(components):
            raise ProtocolError('party must hold exactly three component seeds')
        streams = {j: component_words(seeds[j], registration, j, round_id, padded, word_bits) for j in components}
        for offset in range(0, padded, per_chunk):
            # Circuit visits components 0..3; each party contributes once to its three.
            for j in range(4):
                if j in seeds:
                    yield from streams[j][offset:offset + per_chunk]


def registration_words(component_seeds, party):
    """Actual decrypted registration seeds, checked in MPC before any round."""
    components=held_components(party)
    for seeds in component_seeds:
        if set(seeds)!=set(components):
            raise ProtocolError('party must hold exactly three registration seeds')
        for component in range(4):
            if component in seeds:
                seed=seeds[component]
                if type(seed) is not bytes or len(seed)!=16:
                    raise ProtocolError('invalid registration component seed')
                value=int.from_bytes(seed,'big')
                yield value & ((1<<64)-1)
                yield value >> 64

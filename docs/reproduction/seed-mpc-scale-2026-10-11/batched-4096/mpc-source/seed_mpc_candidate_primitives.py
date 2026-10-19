"""Candidate helpers; replicated-ring input uses full-width conversion.

This file does not establish external client/aggregator composition security.
"""
from Compiler.types import sint, cint, personal, regint, Array
from Compiler.instructions import writesockets
from Compiler.GC.types import sbitvec, sbitintvec
from Compiler.library import listen_for_clients, accept_client_connection, runtime_error_if
from Compiler.program import Program


def tree_reduce(values, operation):
    values = list(values)
    while len(values) > 1:
        values = [operation(values[i], values[i+1]) if i+1 < len(values) else values[i]
                  for i in range(0, len(values), 2)]
    return values[0]


def register_rep4_keys(config):
    Program.prog.active = True
    n, k = config['clients'], config['ring_bits']
    port = config['client_port']
    listen_for_clients(port)
    sockets = Array(n, regint)
    seen = Array(n, regint)
    seen.assign_all(0)
    for _ in range(n):
        cid = accept_client_connection(port)
        runtime_error_if((cid < 0) + (cid >= n), 'invalid seed client id')
        runtime_error_if(seen[cid] != 0, 'duplicate seed client id')
        seen[cid] = 1
        sockets[cid] = cid
    encoding = config['seed_encoding']
    size = 2 if encoding == 'packed64' else 128
    rows, response_differences = [], []
    for i in range(n):
        triples = [value for _ in range(size) for value in sint.get_random_triple()]
        # WRITESOCKETS packs the full three-component Rep4 share (no SPDZ MAC).
        writesockets(sockets[i], 0, triples[0].size, *triples)
        received = cint.read_from_socket(sockets[i],size)
        row = []
        for j in range(size):
            copies = [sint(personal(p, received[j])) for p in range(4)]
            response_differences += [x-copies[0] for x in copies[1:]]
            row.append(copies[0]-triples[3*j])
        rows.append(row)
    # Vectorize full-width conversion; never reduce width to application bits.
    difference_bits = sbitvec(sint.concat(response_differences),length=k,input_length=k)
    bad_per_response = tree_reduce(difference_bits.v,lambda a,b: a | b)
    bad_response = tree_reduce(bad_per_response.bit_decompose(len(response_differences)),lambda a,b: a | b)
    runtime_error_if(regint.conv(bad_response.reveal()) != 0, 'inconsistent seed response')
    keys, invalid = [], []
    for row in rows:
        key_bits = []
        # SIMD columns are input words; each row below is one bit position.
        converted = sbitvec(sint.concat(row),length=k,input_length=k)
        if encoding == 'packed64':
            for value in converted.elements():
                bits = value.bit_decompose(k)
                key_bits += bits[:64]
                invalid += bits[64:]
        else:
            key_bits = converted.v[0].bit_decompose(size)
            bad_per_input = tree_reduce(converted.v[1:],lambda a,b: a | b)
            invalid += bad_per_input.bit_decompose(size)
        keys.append(sbitvec.from_vec(key_bits))
    if invalid:
        bad = tree_reduce(invalid, lambda a,b: a | b)
        runtime_error_if(regint.conv(bad.reveal()) != 0, 'invalid Boolean seed input')
    # In a 64-bit ring two full words are intrinsically a 128-bit key.
    # Packed words have no Boolean-input claim or probabilistic bit check.
    return keys, sockets


def binary_coordinate(encrypted, j, word_bits, y, cap):
    """Exact mod-2^w subtraction, then signed range test without arithmetic LTZ."""
    integer_type = sbitintvec.get_type(word_bits)
    mask = integer_type.from_vec(encrypted.v[128-(j+1)*word_bits:128-j*word_bits])
    signed = integer_type(y) - mask
    coordinate_ok = (signed >= -cap) & (signed <= cap)
    safe_bits = [b & coordinate_ok.v[0] for b in signed.v]
    # sint(sbitvec) is UNSIGNED: subtract sign*2^w explicitly.
    safe_unsigned = sint(sbitvec.from_vec(safe_bits))
    safe = safe_unsigned - (1 << word_bits) * sint(sbitvec.from_vec([safe_bits[-1]]))
    return safe, coordinate_ok.v[0]

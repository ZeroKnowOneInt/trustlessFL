"""Pinned MP-SPDZ compiler helpers, no clear-key reconstruction."""
from Compiler.types import sint, regint, Array
from Compiler.GC.types import sbitvec
from Compiler.library import listen_for_clients, accept_client_connection, runtime_error_if
from Compiler.program import Program
from Compiler.circuit import Circuit


def register_keys(config):
    program = Program.prog
    program.active = True
    n = config['clients']
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
    # Commit all external inputs before creating fresh random bit checks.
    rows = [sint.receive_from_client(128, sockets[i]) for i in range(n)]
    check = sint(0)
    for row in rows:
        for bit in row:
            check += sint.get_random() * bit * (bit - 1)
    opened = check.reveal()
    digits = opened.bit_decompose(config['backend_prime'].bit_length())
    runtime_error_if(sum(regint.conv(b) for b in digits) != 0,
                     'invalid Boolean seed input')
    # Each bit has a validated range; never truncate a whole 128-bit key in Fp.
    def binary_bit(bit):
        arithmetic_pad, binary_pad = sint.get_dabit()
        masked = (bit + arithmetic_pad - 2*bit*arithmetic_pad).reveal()
        return binary_pad ^ masked
    keys = [sbitvec.from_vec([binary_bit(b) for b in row]) for row in rows]
    return keys, sockets


def aes_words(aes, key, counter, word_bits=16):
    plaintext = sbitvec.get_type(128)(counter)
    encrypted = aes(key, plaintext)
    # Bristol/MP-SPDZ vectors use little-endian bit order. Wire words are big-endian.
    return [sint(sbitvec.from_vec(encrypted.v[128-(j+1)*word_bits:128-j*word_bits]))
            for j in range(128 // word_bits)]

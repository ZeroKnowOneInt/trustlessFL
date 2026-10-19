"""Small TLS ExternalIO registration transport for seeded-component sessions.

Implements MP-SPDZ 0.4.3 length-prefixed client-id/specification/public-tag wire
format only. No private-input triples, seed transmission, compiler or native
backend imports. The four signed encrypted seed packets are a separate channel.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import ssl
import struct
import time

from .crypto import ProtocolError
from .seed_mpc_assets import write_private
from .seed_mpc_committee import digest_words
from .seed_mpc_prss import MASK_MODE

TRANSPORT = 'packaged-seeded-registration-v1'


def receive_exact(sock, length):
    body = bytearray()
    while len(body) < length:
        piece = sock.recv(length - len(body))
        if not piece:
            raise ProtocolError('registration connection closed')
        body.extend(piece)
    return bytes(body)


def receive_frame(sock):
    length = struct.unpack('<I', receive_exact(sock, 4))[0]
    if length > 64:
        raise ProtocolError('oversized registration specification')
    return receive_exact(sock, length)


def send_frame(sock, body):
    sock.sendall(struct.pack('<I', len(body)) + body)


def validate_config(config, slot, tag):
    hosts = config.get('party_hosts')
    port = config.get('client_port')
    if (config.get('mask_mode') != MASK_MODE or config.get('parties') != 4
            or config.get('ring_bits') != 64 or config.get('domain_modulus') != 1 << 64
            or config.get('output_mode') != 'native-public'
            or type(slot) is not int or not 0 <= slot < config.get('clients', 0)
            or not isinstance(hosts, list) or len(hosts) != 4
            or any(not isinstance(h, str) or not h for h in hosts)
            or type(port) is not int or not 1024 <= port <= 65531
            or not isinstance(tag, str) or len(tag) != 64):
        raise ProtocolError('unsupported packaged registration configuration')
    try:
        if len(bytes.fromhex(tag)) != 32:
            raise ValueError()
    except ValueError as exc:
        raise ProtocolError('invalid registration digest') from exc


def register(config, slot, tag, *, directory, timeout=60):
    validate_config(config, slot, tag)
    directory = Path(directory)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(directory / f'C{slot}.pem', directory / f'C{slot}.key')
    ctx.load_verify_locations(capath=str(directory))
    sockets = []
    try:
        for party, host in enumerate(config['party_hosts']):
            deadline = time.monotonic() + timeout
            while True:
                try:
                    plain = socket.create_connection((host, config['client_port'] + party), timeout=10)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.2)
            try:
                # MP-SPDZ uses this public slot before the mutual TLS handshake.
                send_frame(plain, str(slot).encode('ascii'))
                secure = ctx.wrap_socket(plain, server_hostname=f'P{party}')
            except BaseException:
                plain.close()
                raise
            sockets.append(secure)
            expected = ssl.PEM_cert_to_DER_cert((directory / f'P{party}.pem').read_text())
            if hashlib.sha256(secure.getpeercert(binary_form=True)).digest() != hashlib.sha256(expected).digest():
                raise ProtocolError('registration peer certificate differs')
        specifications = [receive_frame(s) for s in sockets]
        if any(s != specifications[0] for s in specifications):
            raise ProtocolError('inconsistent registration specification')
        if specifications[0] != struct.pack('<iii', ord('R'), 64, 64):
            raise ProtocolError('registration requires the agreed 64-bit ring')
        payload = b''.join(struct.pack('<Q', word % (1 << 64)) for word in digest_words(tag))
        for secure in sockets:
            send_frame(secure, payload)
        # Scope is application framing, excludes TLS/TCP headers and handshake.
        return {'connection': {'sent_bytes': 4 * (4 + len(str(slot))), 'received_bytes': 4 * 16,
                               'sent_messages': 4, 'received_messages': 4},
                'seed_registration': {'sent_bytes': 4 * (4 + len(payload)), 'received_bytes': 0,
                                      'sent_messages': 4, 'received_messages': 0}}
    finally:
        for secure in sockets:
            secure.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-input', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--communication-output', type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    private = json.loads(args.private_input.read_text())
    counters = register(config, private['client_id'], private['registration_digest'], directory=Path('Player-Data'))
    write_private(args.output, b'{"pending_values":[],"private_seed_inputs":1,"input_submitted":true}')
    if args.communication_output:
        write_private(args.communication_output, json.dumps(counters).encode())


if __name__ == '__main__':
    main()

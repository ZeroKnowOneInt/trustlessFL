"""Local native client. Inputs a seed ONCE, receives pending probe outputs.

Probe mutations remain test-only. Joint-collusion composition proof is pending.
"""
import argparse
import json
import os
from pathlib import Path
import sys

from .crypto import ProtocolError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mp-spdz-dir', type=Path, required=True)
    parser.add_argument('--private-input', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--communication-output', type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    private = json.loads(args.private_input.read_text())
    component_mode = config.get('mask_mode') == 'rep4-seeded-components-v1'
    if not component_mode:
        key = bytes.fromhex(private['seed_key'] if 'seed_key' in private else private['fixture_key'])
        if len(key) != 16:
            raise ProtocolError('invalid AES-128 key')
        integer = int.from_bytes(key, 'big')
        bits = [(integer >> i) & 1 for i in range(128)]
        encoding = config.get('seed_encoding', 'bits')
        if encoding == 'packed64':
            bits = [integer & ((1 << 64)-1), integer >> 64]
        if private.get('mutation') == 'nonboolean':
            if encoding != 'bits': raise ProtocolError('Boolean mutation requires bit input')
            bits[0] = 2
        if private.get('mutation') == 'nonboolean-high':
            if encoding != 'bits': raise ProtocolError('Boolean mutation requires bit input')
            bits[0] = 1 << (config['ring_bits']-1)
    sys.path.insert(0, str(args.mp_spdz_dir.resolve()/'ExternalIO'))
    from client import Client, octetStream
    # Optional probe-only counters: application messages and four-byte framing,
    # excluding TLS records, handshake, and TCP/IP headers. Never record contents.
    stage = 'connection'
    communication = {}
    original_send, original_receive = octetStream.Send, octetStream.Receive
    if args.communication_output:
        def counted_send(stream, sock):
            original_send(stream, sock)
            bucket = communication.setdefault(stage, {'sent_bytes': 0, 'received_bytes': 0,
                                                       'sent_messages': 0, 'received_messages': 0})
            bucket['sent_bytes'] += len(stream) + 4
            bucket['sent_messages'] += 1

        def counted_receive(stream, sock):
            original_receive(stream, sock)
            bucket = communication.setdefault(stage, {'sent_bytes': 0, 'received_bytes': 0,
                                                       'sent_messages': 0, 'received_messages': 0})
            bucket['received_bytes'] += len(stream) + 4
            bucket['received_messages'] += 1

        octetStream.Send, octetStream.Receive = counted_send, counted_receive
    client = Client(['127.0.0.1']*config['parties'], config['client_port'], private['client_id'])
    try:
        if client.domain.modulus != config.get('domain_modulus', config['backend_prime']):
            raise ProtocolError('backend field mismatch')
        stage = 'seed_registration'
        if component_mode:
            # Seeds travel once in recipient-encrypted signed packets. This
            # existing TLS channel binds the client slot to the registration tag.
            from .seed_mpc_committee import digest_words
            tag=digest_words(private['registration_digest'])
            for sock in client.sockets:
                stream=octetStream()
                for word in tag: client.domain(word).pack(stream)
                stream.Send(sock)
        elif config.get('rep4_input_mode') == 'replicated-triples-v1':
            from .rep4_external import reconstruct_replicated_triples
            messages = []
            for socket_index,sock in enumerate(client.sockets):
                stream = octetStream(); stream.Receive(sock)
                if private.get('mutation') == 'tamper-triple' and socket_index == 0:
                    body = bytearray(stream.buf)
                    body[config['ring_bits']//8-1] ^= 0x80
                    stream.buf = bytes(body)
                messages.append(stream.buf)
            triples = reconstruct_replicated_triples(messages,len(bits),config['ring_bits'])
            for socket_index,sock in enumerate(client.sockets):
                stream = octetStream()
                for j,(value,triple) in enumerate(zip(bits,triples)):
                    masked = value+triple[0]
                    if private.get('mutation') == 'equivocate' and socket_index == 0 and j == 0:
                        masked += 1 << (config['ring_bits']-1)
                    client.domain(masked).pack(stream)
                stream.Send(sock)
            if config.get('certified_stream'):
                from .seed_mpc_committee import digest_words
                tag=digest_words(private['registration_digest'])
                for sock in client.sockets:
                    stream=octetStream()
                    for word in tag: client.domain(word).pack(stream)
                    stream.Send(sock)
        else:
            client.send_private_inputs(bits)
        stage = 'final_outputs'
        public_output = config.get('output_mode') == 'native-public'
        result = [] if public_output else client.receive_outputs(config['output_length'])
        # Pending until all native processes have completed their authentication checks.
        fd = os.open(args.output, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump({'pending_values': result, 'private_seed_inputs': 1,
                       **({'input_submitted': True} if public_output else {})}, out)
        if args.communication_output:
            fd = os.open(args.communication_output, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as out:
                json.dump(communication, out, indent=2)
    finally:
        for sock in client.sockets:
            sock.close()


if __name__ == '__main__':
    main()

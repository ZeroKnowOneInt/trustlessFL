"""Authenticated, encrypted peer transport beside Flower.

Aggregator consensus transcripts and signed client-update deliveries have
distinct sender permissions. This is a transport building block, not a full
HotStuff pacemaker. Peer listeners survive Flower's ServerApp failure.
"""

from __future__ import annotations

import asyncio
import json
import math
import secrets
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import Identity, ProtocolError, canonical, digest, verify
from .protocol import Parameters

MAX_MESSAGE = 16 * 1024 * 1024
# Hex encoding doubles the encrypted inner envelope's wire size.
MAX_FRAME = 2 * MAX_MESSAGE + 4096
MAX_RECENT_NONCES = 65536
KINDS = frozenset({"genesis", "roster", "proposal", "vote", "qc", "timeout", "new-view",
                   "decision", "decision-qc", "decision-proof", "client-update", "updates", "hotstuff",
                   "mgf-admit", "mgf-cohort"})
Handler = Callable[[str, str, dict], Awaitable[dict | None]]


def _peer_aad(task: str, sender: str, recipient: str) -> bytes:
    return canonical({"protocol": "aion-peer-seal-v1", "task": task,
                      "sender": sender, "recipient": recipient})


def _peer_key(shared: bytes, associated: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=None,
                info=b"trustlessfl/aion/peer-seal/v1/" + associated).derive(shared)


def seal_peer(envelope: dict, recipient: str, registry: dict, task: str) -> dict:
    """Encrypt a signed envelope to a pinned aggregator with an ephemeral key."""
    try:
        sender = envelope["sender"]
        if not isinstance(sender, str) or not isinstance(recipient, str):
            raise ProtocolError("invalid peer identities")
        plaintext = canonical(envelope)
        if len(plaintext) > MAX_MESSAGE:
            raise ProtocolError("oversized peer message")
        peer_key = X25519PublicKey.from_public_bytes(bytes.fromhex(registry[recipient]["encryption"]))
        ephemeral = X25519PrivateKey.generate()
        associated = _peer_aad(task, sender, recipient)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(_peer_key(ephemeral.exchange(peer_key), associated)).encrypt(
            nonce, plaintext, associated)
        return {"sender": sender, "recipient": recipient,
                "ephemeral": ephemeral.public_key().public_bytes_raw().hex(),
                "nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError("peer encryption failed") from exc


def open_peer(packet: dict, identity: Identity, registry: dict, task: str) -> dict:
    """Authenticate the encryption and the inner signature; reject plaintext."""
    try:
        sender, recipient = packet["sender"], packet["recipient"]
        if (not isinstance(sender, str) or sender not in registry or sender == identity.name
                or recipient != identity.name or not isinstance(packet["ephemeral"], str)
                or len(packet["ephemeral"]) != 64 or not isinstance(packet["nonce"], str)
                or len(packet["nonce"]) != 24 or not isinstance(packet["ciphertext"], str)
                or len(packet["ciphertext"]) > 2 * (MAX_MESSAGE + 16)):
            raise ProtocolError("invalid encrypted peer packet")
        ephemeral = X25519PublicKey.from_public_bytes(bytes.fromhex(packet["ephemeral"]))
        associated = _peer_aad(task, sender, identity.name)
        plaintext = AESGCM(_peer_key(identity.encryption.exchange(ephemeral), associated)).decrypt(
            bytes.fromhex(packet["nonce"]), bytes.fromhex(packet["ciphertext"]), associated)
        if len(plaintext) > MAX_MESSAGE:
            raise ProtocolError("oversized peer message")
        envelope = json.loads(plaintext)
        if not isinstance(envelope, dict):
            raise ProtocolError("invalid encrypted peer envelope")
        verify(envelope, registry, sender=sender)
        return envelope
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError("peer decryption failed") from exc


def _frame(value: dict) -> bytes:
    data = canonical(value)
    if len(data) > MAX_FRAME:
        raise ProtocolError("oversized peer message")
    return len(data).to_bytes(4, "big") + data


async def _read(reader: asyncio.StreamReader) -> dict:
    size = int.from_bytes(await reader.readexactly(4), "big")
    if not 0 < size <= MAX_FRAME:
        raise ProtocolError("invalid peer frame length")
    value = json.loads(await reader.readexactly(size))
    if not isinstance(value, dict):
        raise ProtocolError("invalid peer frame")
    return value


class PeerTransport:
    """Pinned-identity encrypted TCP for consensus and client-update delivery.

    The caller owns durable vote locks and replay-safe consensus state. This
    transport's replay cache is process-local and is not a substitute for
    HotStuff's persistent high-QC/lock state.
    """

    def __init__(self, identity: Identity, parameters: Parameters, registry: dict,
                 addresses: Mapping[str, tuple[str, int]], handler: Handler):
        if registry.get(identity.name) != identity.public():
            raise ProtocolError("peer identity is not pinned")
        if identity.name in parameters.aggregators:
            self.client_outbound = False
            expected_addresses = set(parameters.aggregators) - {identity.name}
        elif identity.name in parameters.clients:
            self.client_outbound = True
            expected_addresses = set(parameters.aggregators)
        else:
            raise ProtocolError("peer identity is outside the task roster")
        if set(addresses) != expected_addresses:
            raise ProtocolError("peer address map has the wrong aggregator roster")
        if any(not isinstance(host, str) or not host or type(port) is not int or not 0 < port < 65536
               for host, port in addresses.values()):
            raise ProtocolError("invalid peer address")
        self.identity = identity
        self.p = parameters
        self.registry = registry
        self.addresses = dict(addresses)
        self.handler = handler
        self.server: asyncio.AbstractServer | None = None
        self.seen: set[tuple[str, str]] = set()
        self.seen_order: deque[tuple[str, str]] = deque()

    async def start(self, host: str, port: int) -> tuple[str, int]:
        if self.client_outbound:
            raise ProtocolError("client peer transport is outbound only")
        if self.server is not None:
            raise ProtocolError("peer listener already running")
        self.server = await asyncio.start_server(self._serve, host, port)
        address = self.server.sockets[0].getsockname()
        return str(address[0]), int(address[1])

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def send(self, recipient: str, kind: str, transcript: dict,
                   *, timeout: float = 10.0) -> dict:
        if (recipient not in self.addresses or kind not in KINDS
                or (self.client_outbound and kind != "client-update")
                or (not self.client_outbound and kind == "client-update")
                or not isinstance(transcript, dict)):
            raise ProtocolError("invalid peer message")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ProtocolError("invalid peer timeout")
        body = {"protocol": "aion-peer-v1", "task": self.p.task,
                "recipient": recipient, "kind": kind,
                "nonce": secrets.token_hex(16), "transcript": transcript}
        request = self.identity.sign(body)

        async def exchange() -> dict:
            reader, writer = await asyncio.open_connection(*self.addresses[recipient])
            try:
                writer.write(_frame(seal_peer(request, recipient, self.registry, self.p.task)))
                await writer.drain()
                response = open_peer(await _read(reader), self.identity, self.registry, self.p.task)
                ack = verify(response, self.registry, sender=recipient)
                if (ack.get("protocol") != "aion-peer-ack-v1" or ack.get("task") != self.p.task
                        or ack.get("recipient") != self.identity.name
                        or ack.get("request") != digest(request)
                        or ack.get("status") != "accepted"):
                    raise ProtocolError("invalid peer acknowledgement")
                return response
            finally:
                writer.close()
                # A quorum caller may cancel its remaining requests after
                # peers have started handling them. Closing that socket can
                # race with the server's signed ACK; preserve the original
                # request result instead of surfacing a teardown error.
                with suppress(OSError):
                    await writer.wait_closed()

        try:
            return await asyncio.wait_for(exchange(), timeout)
        except (OSError, EOFError, asyncio.IncompleteReadError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
            raise ProtocolError("peer delivery failed") from exc

    async def request(self, recipient: str, kind: str, transcript: dict,
                      *, timeout: float = 10.0) -> dict:
        """Return a separately signed party vote carried in the signed ACK."""
        ack = await self.send(recipient, kind, transcript, timeout=timeout)
        result = verify(ack, self.registry, sender=recipient).get("result")
        if not isinstance(result, dict):
            raise ProtocolError("peer did not return a vote")
        verify(result, self.registry, sender=recipient)
        return result

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            packet = await asyncio.wait_for(_read(reader), 10.0)
            request = open_peer(packet, self.identity, self.registry, self.p.task)
            body = verify(request, self.registry)
            if not isinstance(body, dict):
                raise ProtocolError("invalid peer envelope")
            sender = request["sender"]
            nonce = body.get("nonce")
            if ((sender not in self.p.aggregators and sender not in self.p.clients)
                    or (sender in self.p.clients and body.get("kind") != "client-update")
                    or (sender in self.p.aggregators and body.get("kind") == "client-update")
                    or sender == self.identity.name
                    or body.get("protocol") != "aion-peer-v1" or body.get("task") != self.p.task
                    or body.get("recipient") != self.identity.name or body.get("kind") not in KINDS
                    or not isinstance(body.get("transcript"), dict)
                    or not isinstance(nonce, str) or len(nonce) != 32
                    or any(c not in "0123456789abcdef" for c in nonce)):
                raise ProtocolError("invalid peer envelope")
            token = (sender, nonce)
            if token in self.seen:
                raise ProtocolError("replayed peer envelope")
            if len(self.seen_order) == MAX_RECENT_NONCES:
                self.seen.remove(self.seen_order.popleft())
            self.seen.add(token)
            self.seen_order.append(token)
            result = await self.handler(sender, body["kind"], body["transcript"])
            if result is not None:
                if not isinstance(result, dict):
                    raise ProtocolError("invalid peer handler result")
                verify(result, self.registry, sender=self.identity.name)
            ack = self.identity.sign({"protocol": "aion-peer-ack-v1", "task": self.p.task,
                                      "recipient": sender, "request": digest(request),
                                      "status": "accepted", "result": result})
            writer.write(_frame(seal_peer(ack, sender, self.registry, self.p.task)))
            await writer.drain()
        except (ProtocolError, ValueError, KeyError, TypeError, OverflowError, OSError, asyncio.TimeoutError,
                asyncio.IncompleteReadError, json.JSONDecodeError):
            # Never reflect potentially sensitive application data in an error.
            pass
        finally:
            writer.close()
            with suppress(OSError):
                await writer.wait_closed()

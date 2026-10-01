"""Bounded Flower chunks for large, unchanged AION protocol envelopes.

Only transport bytes are staged here. Application signatures and certificates
are still checked by their original handlers after complete hash verification.
"""

import base64
import fcntl
import hashlib
import json
import os
import tempfile
from pathlib import Path

from .crypto import Identity, ProtocolError, canonical, digest
from .protocol import Parameters

PAYLOAD_LIMIT = 16 * 1024 * 1024
CHUNK_BYTES = 4 * 1024 * 1024
MAX_BLOB_BYTES = 1024 * 1024 * 1024
WIRE_ACTIONS = {"wire_write", "wire_read", "wire_execute", "wire_release"}


def validate_blob(tag, size):
    if (not isinstance(tag, str) or len(tag) != 64
            or any(c not in "0123456789abcdef" for c in tag)
            or type(size) is not int or not 1 <= size <= MAX_BLOB_BYTES):
        raise ProtocolError("invalid Flower blob descriptor")


def _settings(config):
    identity_path = Path(str(config["aion-identity"]))
    manifest = json.loads(Path(str(config["aion-manifest"])).read_text())
    if manifest.get("research-mode") is not True:
        raise ProtocolError("Flower blob requires research opt-in")
    p = Parameters.from_dict(manifest["parameters"])
    identity = Identity.from_private(json.loads(identity_path.read_text()))
    if manifest["registry"].get(identity.name) != identity.public():
        raise ProtocolError("Flower blob identity is not pinned")
    root = identity_path.parent / ("flower-wire-" + digest({"task": p.task, "party": identity.name}))
    root.mkdir(mode=0o700, exist_ok=True)
    return p, identity, root


def _path(root, direction, tag):
    if direction not in ("in", "out"):
        raise ProtocolError("invalid Flower blob direction")
    return root / f"{direction}-{tag}.bin"


def _offset(offset, size):
    if type(offset) is not int or not 0 <= offset < size or offset % CHUNK_BYTES:
        raise ProtocolError("invalid Flower chunk offset")
    return min(CHUNK_BYTES, size - offset)


def transport_request(config, request):
    """Return (signed response, None) or (None, reconstructed request)."""
    action = request.get("action")
    if action not in WIRE_ACTIONS:
        return None, request
    p, identity, root = _settings(config)
    tag, size = request.get("digest"), request.get("size")
    validate_blob(tag, size)
    if action == "wire_release":
        direction = request.get("direction")
        target = _path(root, direction, tag)
        if direction == "in":
            with (root / f"in-{tag}.lock").open("a+b") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                target.unlink(missing_ok=True)
                target.with_suffix(".part").unlink(missing_ok=True)
        else:
            target.unlink(missing_ok=True)
        return identity.sign(p.claim("wire-released", 0, digest=tag, size=size)), None
    if action == "wire_write":
        offset = request.get("offset")
        width = _offset(offset, size)
        encoded = request.get("data")
        if not isinstance(encoded, str) or len(encoded) != 4 * ((width + 2) // 3):
            raise ProtocolError("invalid Flower upload chunk")
        try:
            chunk = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ProtocolError("invalid Flower chunk encoding") from exc
        if len(chunk) != width:
            raise ProtocolError("invalid Flower chunk length")
        target = _path(root, "in", tag)
        partial = target.with_suffix(".part")
        with (root / f"in-{tag}.lock").open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if target.exists():
                if target.stat().st_size != size:
                    raise ProtocolError("conflicting Flower upload size")
                with target.open("rb") as stream:
                    stream.seek(offset)
                    if stream.read(width) != chunk:
                        raise ProtocolError("conflicting Flower upload retry")
            else:
                current = partial.stat().st_size if partial.exists() else 0
                if current > size or current < offset:
                    raise ProtocolError("out-of-order Flower upload")
                with partial.open("r+b" if partial.exists() else "w+b") as stream:
                    os.chmod(partial, 0o600)
                    stream.seek(offset)
                    if offset < current:
                        if current < offset + width or stream.read(width) != chunk:
                            raise ProtocolError("conflicting Flower upload retry")
                    else:
                        stream.write(chunk)
                        stream.flush()
                        os.fsync(stream.fileno())
                if partial.stat().st_size == size:
                    with partial.open("rb") as stream:
                        valid = hashlib.file_digest(stream, "sha256").hexdigest() == tag
                    if not valid:
                        partial.unlink(missing_ok=True)
                        raise ProtocolError("Flower upload digest mismatch")
                    os.replace(partial, target)
        return identity.sign(p.claim("wire-stored", 0, digest=tag, size=size,
                                     offset=offset, length=width)), None
    if action == "wire_read":
        offset = request.get("offset")
        width = _offset(offset, size)
        path = _path(root, "out", tag)
        if not path.exists() or path.stat().st_size != size:
            raise ProtocolError("missing Flower response blob")
        with path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(width)
        return identity.sign(p.claim("wire-chunk", 0, digest=tag, size=size, offset=offset,
                                     data=base64.b64encode(data).decode("ascii"))), None
    path = _path(root, "in", tag)
    if not path.exists() or path.stat().st_size != size:
        raise ProtocolError("missing Flower request blob")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != tag:
        raise ProtocolError("Flower request digest mismatch")
    command = json.loads(raw)
    if not isinstance(command, dict) or command.get("action") in WIRE_ACTIONS:
        raise ProtocolError("invalid reconstructed Flower command")
    return None, command


def transport_response(config, response):
    raw = canonical(response)
    if len(raw) <= PAYLOAD_LIMIT:
        return response
    tag, size = hashlib.sha256(raw).hexdigest(), len(raw)
    validate_blob(tag, size)
    p, identity, root = _settings(config)
    path = _path(root, "out", tag)
    if not path.exists():
        fd, temporary = tempfile.mkstemp(prefix=".response-", dir=root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return identity.sign(p.claim("wire-result", 0, digest=tag, size=size))

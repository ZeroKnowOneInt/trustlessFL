"""Both silo and independent aggregator actors run as Flower ClientApps.

Flower's ClientApp transport role is distinct from the AION training-client
role. An aggregator actor never trains on silo data.
"""

import fcntl
import json
import os
import tempfile
from pathlib import Path

from flwr.app import ConfigRecord, Context, Error, Message, RecordDict
from flwr.clientapp import ClientApp

from .crypto import Identity, ProtocolError, canonical
from .protocol import Parameters, Party

app = ClientApp()
ACTIONS = {"hello", "enroll", "initialize", "train", "prepare", "share", "finalize", "commit"}


def records(payload: dict) -> RecordDict:
    # JSON bytes preserve >64-bit field elements which ConfigRecord integers cannot.
    return RecordDict({"aion": ConfigRecord({"payload": canonical(payload)})})


def payload(message: Message) -> dict:
    data = message.content["aion"]["payload"]
    if not isinstance(data, bytes) or len(data) > 16 * 1024 * 1024:
        raise ProtocolError("invalid or oversized AION payload")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ProtocolError("expected an AION object")
    return result


def save_state(path: Path, state: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".aion-state-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(state))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@app.query("aion")
def handle(message: Message, context: Context) -> Message:
    """Process one request with node-local identity, manifest and durable locks."""
    try:
        manifest_path = Path(str(context.node_config["aion-manifest"]))
        identity_path = Path(str(context.node_config["aion-identity"]))
        manifest = json.loads(manifest_path.read_text())
        if manifest.get("research-mode") is not True:
            raise ProtocolError("only explicitly opted-in research runs are supported")
        p = Parameters.from_dict(manifest["parameters"])
        identity = Identity.from_private(json.loads(identity_path.read_text()))
        request = payload(message)
        action = request["action"]
        if action not in ACTIONS:
            raise ProtocolError("unknown AION action")
        # Task-scoped state survives transient ClientApp instances and restarts.
        from .crypto import digest
        filename = digest({"task": p.task, "party": identity.name})
        state_path = identity_path.parent / f"state-{filename}.json"
        lock_path = identity_path.parent / f"state-{filename}.lock"
        with lock_path.open("a+b") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
            trainer = None
            if "endpoint-shard" in context.node_config:
                if identity.name not in p.clients or "mnist-shard" in context.node_config:
                    raise ProtocolError("invalid endpoint training role")
                from .endpoint_aion import EndpointTrainer
                trainer = EndpointTrainer(
                    context.node_config["endpoint-shard"], context.node_config["endpoint-seed"],
                    context.node_config["endpoint-epochs"], context.node_config["endpoint-batch-size"],
                    context.node_config["endpoint-device"])
            if "mnist-shard" in context.node_config:
                if identity.name not in p.clients:
                    raise ProtocolError("aggregators must not have training data")
                from .mnist import MnistTrainer
                trainer = MnistTrainer(str(context.node_config["mnist-shard"]),
                                       int(context.node_config.get("mnist-seed", 42)),
                                       int(context.node_config.get("mnist-batch-size", 256)))
            party = Party(identity, p, manifest["registry"], state, trainer=trainer)
            response = getattr(party, action)(request)
            if "endpoint-shard" in context.node_config and trainer.meta is not None:
                party.state.setdefault("training_meta", {})[str(trainer.meta["round"])] = trainer.meta
            # Persist the lock BEFORE releasing any signature or share.
            save_state(state_path, party.state)
        return Message(records(response), reply_to=message)
    except (ProtocolError, ValueError, KeyError, TypeError, OverflowError):
        # No input values, shares or exception representations in diagnostics.
        return Message(error=Error(code=400, reason="AION request rejected"), reply_to=message)

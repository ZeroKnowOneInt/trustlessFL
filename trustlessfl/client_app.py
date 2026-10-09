"""Both silo and independent aggregator actors run as Flower ClientApps.

Flower's ClientApp transport role is distinct from the AION training-client
role. An aggregator actor never trains on silo data.
"""

import asyncio
import fcntl
import json
import os
import tempfile
from functools import lru_cache
from pathlib import Path

from flwr.app import ConfigRecord, Context, Error, Message, RecordDict
from flwr.clientapp import ClientApp

from .crypto import Identity, ProtocolError, canonical, digest, verify
from .peer_transport import PeerTransport
from .protocol import Parameters, Party
from .flower_chunks import MAX_BLOB_BYTES, transport_request, transport_response

app = ClientApp()


@app.query("aion_source_asr")
def handle_source_asr(message: Message, context: Context) -> Message:
    """Separate author-normal-path transport; never enters the custom Party."""
    from .aion_source_asr import flower_source_request
    from .paper_dmc import QuantizedLiftError
    from .aion_source_aggregate import AggregateValidationError
    from .source_paper_numeric import MGFSelectionError
    from .source_profiles import SourceProfileError
    try:
        response = flower_source_request(context.node_config, context.state, payload(message))
        return Message(records(response), reply_to=message)
    except QuantizedLiftError as exc:
        return Message(error=Error(code=400, reason="Author ASR numeric failure: " + exc.code),
                       reply_to=message)
    except AggregateValidationError as exc:
        return Message(error=Error(code=400, reason="Author ASR aggregate validation failure: " + exc.code),
                       reply_to=message)
    except MGFSelectionError as exc:
        return Message(error=Error(code=400, reason="Author ASR MGF selection failure: " + exc.code),
                       reply_to=message)
    except SourceProfileError as exc:
        return Message(error=Error(code=400, reason="Author ASR profile failure: " + exc.code),
                       reply_to=message)
    except (ProtocolError, ValueError, KeyError, TypeError, OverflowError):
        return Message(error=Error(code=400, reason="Author ASR request rejected"), reply_to=message)


ACTIONS = {"hello", "enroll", "initialize", "train", "prepare", "roster_commit", "share", "finalize", "commit", "decide",
           "late_prepare", "late_share", "late_finalize", "view_vote", "recover",
           "proposal_vote", "proposal_proof", "roster_vote", "roster_proof",
           "genesis_vote", "model_status", "hotstuff_candidate", "hotstuff", "mgf_admit", "stage_update",
           "mgf_cohort_vote", "mgf_cohort_share", "mgf_cohort_norm"}
READ_ONLY_ACTIONS = {"hello", "genesis_vote", "model_status",
                     "roster_vote", "roster_proof", "proposal_vote", "proposal_proof",
                     "hotstuff_candidate", "recover", "stage_update"}


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


def peer_decision_path(identity_path: Path, task: str, party: str) -> Path:
    tag = digest({"task": task, "party": party})
    return identity_path.parent / f"peer-decisions-{tag}.json"


def peer_update_path(identity_path: Path, task: str, party: str, round_id: int) -> Path:
    tag = digest({"task": task, "party": party, "round": round_id})
    return identity_path.parent / f"peer-updates-{tag}.json"


def staged_update_path(identity_path: Path, task: str, party: str,
                       round_id: int, client: str) -> Path:
    tag = digest({"task": task, "party": party, "round": round_id, "client": client})
    return identity_path.parent / f"staged-update-{tag}.json"


@lru_cache(maxsize=64)
def _read_public_manifest(path: str) -> dict:
    """Manifest registry/config is shared by all simulated node contexts."""
    return json.loads(Path(path).read_text())


def resolve_staged_prepare(identity_path: Path, p: Parameters, party: str,
                           command: dict) -> dict:
    """Resolve Flower-staged updates locally, keeping HotStuff wire commands small."""
    if command.get("action") != "prepare" or "staged" not in command:
        return command
    references = command["staged"]
    if ("updates" in command or not isinstance(references, list) or not references
            or len(references) > len(p.clients)
            or any(not isinstance(entry, dict)
                   or set(entry) != {"client", "digest"}
                   or entry["client"] not in p.clients
                   or not isinstance(entry["digest"], str)
                   for entry in references)):
        raise ProtocolError("invalid staged roster references")
    if [entry["client"] for entry in references] != [
            c for c in p.clients if c in {entry["client"] for entry in references}]:
        raise ProtocolError("staged roster references are unordered or repeated")
    update_round = command["model"]["body"]["round"] + 1
    updates = []
    for entry in references:
        path = staged_update_path(identity_path, p.task, party,
                                  update_round, entry["client"])
        if not path.exists() or path.stat().st_size > MAX_BLOB_BYTES:
            raise ProtocolError("missing staged client update")
        update = json.loads(path.read_text())
        if digest(update) != entry["digest"]:
            raise ProtocolError("staged update reference mismatch")
        updates.append(update)
    return {**{key: value for key, value in command.items() if key != "staged"},
            "updates": updates}


def deliver_update_to_peers(node_config: dict, update: dict) -> None:
    """Optional dual delivery after Flower training, requiring aggregator ACK quorum."""
    manifest = json.loads(Path(str(node_config["aion-manifest"])).read_text())
    p = Parameters.from_dict(manifest["parameters"])
    identity = Identity.from_private(json.loads(Path(str(node_config["aion-identity"])).read_text()))
    if identity.name not in p.clients or manifest["registry"].get(identity.name) != identity.public():
        raise ProtocolError("peer update delivery requires a pinned client")
    body = verify(update, manifest["registry"], sender=identity.name)
    if not isinstance(body, dict) or body.get("kind") != "update" or body.get("task") != p.task:
        raise ProtocolError("only a signed local update can be delivered")
    raw_addresses = json.loads(Path(str(node_config["aion-peer-addresses"])).read_text())
    if not isinstance(raw_addresses, dict) or any(
            not isinstance(name, str) or not isinstance(address, list) or len(address) != 2
            for name, address in raw_addresses.items()):
        raise ProtocolError("invalid aggregator update address file")
    addresses = {name: (address[0], address[1]) for name, address in raw_addresses.items()}

    async def unused_handler(_sender: str, _kind: str, _transcript: dict) -> None:
        raise ProtocolError("client peer sender is outbound only")

    async def send_all() -> None:
        sender = PeerTransport(identity, p, manifest["registry"], addresses, unused_handler)
        expected = p.claim("update-received", body["round"], client=identity.name,
                           update=digest(update))

        async def send(name: str) -> bool:
            try:
                receipt = await sender.request(name, "client-update",
                                               {"action": "deliver_update", "update": update},
                                               timeout=10.0)
                return verify(receipt, manifest["registry"], sender=name) == expected
            except ProtocolError:
                return False

        tasks = {asyncio.create_task(send(name)) for name in p.aggregators}
        confirmed = 0
        try:
            while tasks and confirmed < p.quorum:
                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                confirmed += sum(task.result() for task in done)
                if confirmed + len(tasks) < p.quorum:
                    break
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        if confirmed < p.quorum:
            raise ProtocolError("signed update did not reach an aggregator quorum")

    asyncio.run(send_all())


def process_local_request(node_config: dict, request: dict) -> dict:
    """Execute a Flower or peer request against the same durable party state."""
    manifest_path = Path(str(node_config["aion-manifest"]))
    identity_path = Path(str(node_config["aion-identity"]))
    manifest = _read_public_manifest(str(manifest_path))
    if manifest.get("research-mode") is not True:
        raise ProtocolError("only explicitly opted-in research runs are supported")
    p = Parameters.from_dict(manifest["parameters"])
    identity = Identity.from_private(json.loads(identity_path.read_text()))
    action = request["action"]
    if action not in ACTIONS:
        raise ProtocolError("unknown AION action")
    # Task-scoped state survives transient ClientApp instances and restarts.
    filename = digest({"task": p.task, "party": identity.name})
    state_path = identity_path.parent / f"state-{filename}.json"
    lock_path = identity_path.parent / f"state-{filename}.lock"
    with lock_path.open("a+b") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
        trainer = None
        if "endpoint-shard" in node_config:
            if identity.name not in p.clients or "mnist-shard" in node_config:
                raise ProtocolError("invalid endpoint training role")
            from .endpoint_aion import EndpointTrainer
            trainer = EndpointTrainer(
                node_config["endpoint-shard"], node_config["endpoint-seed"],
                node_config["endpoint-epochs"], node_config["endpoint-batch-size"],
                node_config["endpoint-device"])
        if "mnist-shard" in node_config:
            if identity.name not in p.clients:
                raise ProtocolError("aggregators must not have training data")
            from .mnist import MnistTrainer
            trainer = MnistTrainer(str(node_config["mnist-shard"]),
                                   int(node_config.get("mnist-seed", 42)),
                                   int(node_config.get("mnist-batch-size", 256)))
        if "fmnist-shard" in node_config:
            if (identity.name not in p.clients or "mnist-shard" in node_config
                    or "endpoint-shard" in node_config):
                raise ProtocolError("invalid FMNIST training role")
            from .fmnist import FmnistTrainer
            trainer = FmnistTrainer(
                node_config["fmnist-shard"], node_config["fmnist-reference"],
                seed=int(node_config.get("fmnist-seed", 1)),
                epochs=int(node_config.get("fmnist-epochs", 2)),
                batch_size=int(node_config.get("fmnist-batch-size", 64)),
                device=str(node_config.get("fmnist-device", "cpu")),
                attack=node_config.get("fmnist-attack"),
                sampling_policy=str(node_config.get("fmnist-sampling-policy", "legacy")))
        party = Party(identity, p, manifest["registry"], state, trainer=trainer)
        party._resolve_staged = lambda command: resolve_staged_prepare(
            identity_path, p, identity.name, command)
        if action == "stage_update":
            if identity.name not in p.aggregators:
                raise ProtocolError("only aggregators may stage signed updates")
            update = request.get("update")
            if not isinstance(update, dict) or update.get("sender") not in p.clients:
                raise ProtocolError("invalid staged client update")
            sender = update["sender"]
            body = verify(update, manifest["registry"], sender=sender)
            round_id = body.get("round") if isinstance(body, dict) else None
            previous = state.get("last_model")
            if (type(round_id) is not int or round_id < 1 or not isinstance(previous, dict)
                    or previous.get("round") != round_id - 1
                    or body.get("parent") != digest(previous)):
                raise ProtocolError("staged update does not extend aggregator model")
            party._expect(update, sender, "update", round_id)
            path = staged_update_path(identity_path, p.task, identity.name, round_id, sender)
            if path.exists():
                if path.stat().st_size > MAX_BLOB_BYTES or json.loads(path.read_text()) != update:
                    raise ProtocolError("conflicting staged update")
            else:
                save_state(path, update)
            response = identity.sign(p.claim("update-staged", round_id,
                                             client=sender, update=digest(update)))
        elif action == "recover":
            if identity.name not in p.aggregators:
                raise ProtocolError("only aggregators can report recovery evidence")
            proof_path = peer_decision_path(identity_path, p.task, identity.name)
            if proof_path.exists():
                if proof_path.stat().st_size > 16 * 1024 * 1024:
                    raise ProtocolError("peer decision store is oversized")
                proof_store = json.loads(proof_path.read_text())
                if (not isinstance(proof_store, dict) or proof_store.get("task") != p.task
                        or not isinstance(proof_store.get("certificates"), dict)):
                    raise ProtocolError("invalid peer decision store")
                proofs = [proof_store["certificates"][key] for key in sorted(
                    proof_store["certificates"], key=int)]
            else:
                proofs = []
            last_model = state.get("last_model")
            last_round = last_model.get("round", -1) if isinstance(last_model, dict) else -1
            response = identity.sign(p.claim("recovery", 0, last_round=last_round, proofs=proofs))
        else:
            request = resolve_staged_prepare(identity_path, p, identity.name, request)
            response = getattr(party, action)(request)
        if "endpoint-shard" in node_config and trainer.meta is not None:
            party.state.setdefault("training_meta", {})[str(trainer.meta["round"])] = trainer.meta
        if "fmnist-shard" in node_config and trainer.meta is not None:
            party.state.setdefault("training_meta", {})[str(trainer.meta["round"])] = trainer.meta
        # These actions inspect durable state but do not mutate it. In a large
        # FMNIST round the pending masked updates can occupy hundreds of MB;
        # rewriting them for each staged update or candidate check dominates
        # the Flower runtime without adding durability.
        if action not in READ_ONLY_ACTIONS:
            # Persist the lock BEFORE releasing any signature or share.
            save_state(state_path, party.state)
        if action == "decide" and identity.name in p.aggregators:
            # Staged copies are only needed while this round can still be
            # prepared or reproposed. Remove them after the decided state is
            # durable, so many-round Flower runs do not accumulate q large
            # update files at every aggregator.
            model = party.state["last_model"]
            members = party.state["pending"]["claim"]["members"]
            for client in members:
                staged_update_path(identity_path, p.task, identity.name,
                                   model["round"], client).unlink(missing_ok=True)
    return response


@app.query("aion")
def handle(message: Message, context: Context) -> Message:
    """Process one Flower request with node-local identity and durable locks."""
    try:
        request = payload(message)
        response, request = transport_request(context.node_config, request)
        if response is not None:
            return Message(records(response), reply_to=message)
        response = process_local_request(context.node_config, request)
        if request.get("action") == "train" and "aion-peer-addresses" in context.node_config:
            deliver_update_to_peers(context.node_config, response)
        return Message(records(transport_response(context.node_config, response)), reply_to=message)
    except (ProtocolError, ValueError, KeyError, TypeError, OverflowError):
        # No input values, shares or exception representations in diagnostics.
        return Message(error=Error(code=400, reason="AION request rejected"), reply_to=message)

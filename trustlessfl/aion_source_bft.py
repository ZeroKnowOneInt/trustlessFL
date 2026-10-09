"""Flower wiring for the source prepare/precommit/commit normal path.

Adapter corrections: pin the sender's public key, use a serializable value ID,
count distinct commit voters, and size the quorum to the actual committee.
No view-change or general liveness claim is made by this normal-path adapter.
"""

import importlib.util
import hashlib
import logging
import sys
from dataclasses import asdict
from pathlib import Path

from Cryptodome.PublicKey import ECC

from .crypto import ProtocolError, digest


def _module(root):
    path = Path(root) / "agent/Aion/bft.py"
    name = "trustlessfl._author_bft_" + digest(str(path))[:16]
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    return sys.modules[name]


def check_source_commit(manifest, proof, registry, round_id, value):
    """Verify the normal-path committee certificate independently of replies."""
    module = _module(manifest["source-root"])
    committee = manifest["committee"]
    if (proof.get("registry") != registry or proof.get("value") != value
            or proof.get("sequence") != round_id):
        raise ProtocolError("source commit proof context mismatch")
    commits = proof.get("commits", [])
    seen = set()
    checker = type("SignatureChecker", (), {"logger": logging.getLogger("trustlessfl.author-bft")})()
    for body in commits:
        sender = body.get("node_id")
        if (sender not in committee or sender in seen or body.get("type") != "commit"
                or body.get("phase") != module.BFTPhase.COMMIT.value
                or body.get("sequence") != round_id or body.get("view") != 0
                or body.get("value") != value):
            raise ProtocolError("invalid source commit voter or phase")
        message = module.BFTMessage(**{**body, "phase": module.BFTPhase(body["phase"])})
        if not module.BFTProtocol._verify_signature(checker, message,
                ECC.import_key(registry[str(sender)])):
            raise ProtocolError("source commit signature invalid")
        seen.add(sender)
    if len(seen) < len(committee) - (len(committee) - 1) // 3:
        raise ProtocolError("source commit quorum unavailable")
    return proof


def source_bft_request(manifest, actor_id, state, request):
    committee = manifest["committee"]
    if actor_id not in committee:
        raise ProtocolError("only committee actors participate in source BFT")
    filename = "agent/Aion/bft.py"
    source_hash = hashlib.sha256((Path(manifest["source-root"]) / filename).read_bytes()).hexdigest()
    if source_hash != manifest["source-sha256"][filename]:
        raise ProtocolError("author BFT source hash mismatch")
    module = _module(manifest["source-root"])
    saved = state.setdefault("source-bft", {})
    if "private" not in saved:
        saved["private"] = ECC.generate(curve="P-256").export_key(format="PEM")
    private = ECC.import_key(saved["private"])
    if request["action"] == "bft-hello":
        return dict(actor=actor_id, public=private.public_key().export_key(format="PEM"))
    registry = request["registry"]
    if set(registry) != {str(name) for name in committee}:
        raise ProtocolError("source BFT registry does not match committee")
    if registry[str(actor_id)] != private.public_key().export_key(format="PEM"):
        raise ProtocolError("source BFT own key mismatch")
    pinned = saved.setdefault("registry", registry)
    if pinned != registry:
        raise ProtocolError("source BFT registry changed")
    round_id = request.get("sequence", request["round"])
    if type(round_id) is not int or not 1 <= round_id <= 2 * manifest["rounds"] + 1:
        raise ProtocolError("invalid source BFT sequence")
    value = request["value"]
    from .aion_source_roster import check_proposal
    check_proposal(manifest, state, request, round_id)
    from .aion_source_aggregate import check_proposal as check_aggregate_proposal
    check_aggregate_proposal(manifest, state, request, round_id)
    values = saved.setdefault("values", {})
    if str(round_id) in values and values[str(round_id)] != value:
        raise ProtocolError("conflicting source BFT value")
    values[str(round_id)] = value

    def decode(body):
        return module.BFTMessage(**{**body, "phase": module.BFTPhase(body["phase"])})

    def encode(message):
        body = asdict(message)
        body["phase"] = message.phase.value
        return body

    class FlowerBFT(module.BFTProtocol):
        def _load_keys(self):
            # Node-local Context state replaces source cwd-relative pki writes.
            self.private_key, self.public_key = private, private.public_key()

        def _verify_message(self, message):
            if (message.node_id not in committee or message.view != 0
                    or message.sequence != round_id or message.value != value
                    or not message.signature):
                return False
            return self._verify_signature(message, ECC.import_key(registry[str(message.node_id)]))

        def _check_consensus(self, sequence):
            votes = [m for m in self.messages.get("commit", []) if m.sequence == sequence]
            return (len({m.node_id for m in votes}) >= self.total_nodes - self.f
                    and {m.value for m in votes} == {value})

    node = FlowerBFT(actor_id, len(committee), (len(committee) - 1) // 3)
    node.logger = logging.getLogger("trustlessfl.author-bft")
    node.sequence = round_id
    node.messages = {kind: [decode(body) for body in messages]
                     for kind, messages in saved.get("messages", {}).items()}
    node.prepared_values = {int(k): set(v) for k, v in saved.get("prepared", {}).items()}
    node.committed_values = {int(k): set(v) for k, v in saved.get("committed", {}).items()}
    cache = saved.setdefault("replies", {})
    tag = digest(request)
    if tag in cache:
        return cache[tag]
    if request["action"] == "bft-prepare":
        response = node.prepare(value, sequence=round_id)
    elif request["action"] == "bft-deliver":
        message = decode(request["message"])
        if not node._verify_message(message):
            raise ProtocolError("invalid source BFT signature or context")
        previous = node.messages.get(message.type, [])
        if any(m.node_id == message.node_id and m.sequence == round_id for m in previous):
            response = None  # The sender is one voter, not one vote per delivery.
        else:
            response = node.handle_message(message)
    else:
        raise ProtocolError("unknown source BFT action")
    saved["messages"] = {kind: [encode(m) for m in messages] for kind, messages in node.messages.items()}
    saved["prepared"] = {str(k): sorted(v) for k, v in node.prepared_values.items()}
    saved["committed"] = {str(k): sorted(v) for k, v in node.committed_values.items()}
    decided = node._check_consensus(round_id)
    result = dict(response=encode(response) if response else None, decided=decided,
                  actor=actor_id, value=value, sequence=round_id)
    cache[tag] = result
    return result

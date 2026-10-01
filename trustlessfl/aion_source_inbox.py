"""Node-local inbox for masked VECTORs delivered through Flower messages.

Only already-received masked envelopes are stored; no training data, plaintext
updates, private keys, VSS shares or caller-supplied filesystem paths are used.
"""

import hashlib
import json
import re
from pathlib import Path

from .aion_source_cohort import round_clients
from .crypto import ProtocolError, canonical, digest


def inbox_root(config, manifest, round_id):
    return (Path(config["aion-source-manifest"]).resolve().parent / "masked-inbox"
            / digest(manifest["task"]) / str(config.get("aion-source-id", manifest["aggregator"])) / str(round_id))


def stage_vectors(config, manifest, state, round_id, vectors):
    actor = config.get("aion-source-id", manifest["aggregator"])
    last_round = (state.get("last_round", 0) if actor == manifest["aggregator"] else
                  state.get("source-selection", {}).get("round", 0))
    if round_id != last_round + 1:
        raise ProtocolError("source inbox round out of order")
    if not isinstance(vectors, list) or not vectors:
        raise ProtocolError("empty source masked vector batch")
    cohort = round_clients(manifest, round_id)
    current = state.get("masked_inbox", {"round": round_id, "entries": {}})
    if current["round"] != round_id:
        current = {"round": round_id, "entries": {}}
    entries = dict(current["entries"])
    prepared = []
    allowed = {"msg", "iteration", "sender", "masked_vector"}
    if manifest.get("workload", "ones") != "ones":
        allowed.add("parent")
    if "paper_numerics" in manifest:
        allowed.add("paper_scale")
    from .aion_source_selection import enabled
    if enabled(manifest):
        allowed.update(("task", "signature"))
    for vector in vectors:
        if (not isinstance(vector, dict) or type(vector.get("sender")) is not int
                or set(vector) != allowed
                or vector["sender"] not in cohort or vector.get("msg") != "VECTOR"
                or type(vector.get("iteration")) is not int or vector["iteration"] != round_id
                or not isinstance(vector.get("masked_vector"), list)
                or len(vector["masked_vector"]) != manifest["dimension"]):
            raise ProtocolError("invalid source masked vector batch")
        sender, tag = str(vector["sender"]), digest(vector)
        if sender in entries and entries[sender] != tag:
            raise ProtocolError("conflicting source masked vector retry")
        entries[sender] = tag
        prepared.append((vector, dict(sender=vector["sender"], digest=tag)))
    root = inbox_root(config, manifest, round_id)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for vector, reference in prepared:
        path = root / f'{reference["sender"]}-{reference["digest"]}.json'
        raw = canonical(vector)
        if path.exists():
            if path.read_bytes() != raw:
                raise ProtocolError("source masked inbox content changed")
        else:
            with path.open("xb") as stream:
                stream.write(raw)
    state["masked_inbox"] = {"round": round_id, "entries": entries}
    return dict(vector_refs=[reference for _, reference in prepared])


def load_vectors(config, manifest, state, round_id, references):
    current = state.get("masked_inbox", {})
    if current.get("round") != round_id or not isinstance(references, list):
        raise ProtocolError("missing source masked inbox")
    cohort = round_clients(manifest, round_id)
    if (len(references) != len(cohort) or
            any(not isinstance(ref, dict) or type(ref.get("sender")) is not int
                or not isinstance(ref.get("digest"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", ref["digest"]) for ref in references)
            or {ref["sender"] for ref in references} != set(cohort)):
        raise ProtocolError("invalid source vector references")
    root = inbox_root(config, manifest, round_id)
    vectors = []
    for reference in references:
        sender, tag = reference["sender"], reference["digest"]
        if current["entries"].get(str(sender)) != tag:
            raise ProtocolError("source masked inbox reference mismatch")
        path = root / f"{sender}-{tag}.json"
        if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            raise ProtocolError("missing or oversized source masked inbox vector")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != tag:
            raise ProtocolError("source masked inbox hash mismatch")
        vector = json.loads(raw)
        if vector["sender"] != sender or vector["iteration"] != round_id:
            raise ProtocolError("source masked inbox context mismatch")
        vectors.append(vector)
    return vectors

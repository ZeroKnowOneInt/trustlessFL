"""Committee replay of a source paper-MGF aggregate before model BFT.

An opening of ONLY the already-authorized sum key binds it to local initial
VSS commitments. Verifiers use their own signed-vector selection snapshot.
No individual key/update or new mask share is disclosed. This is an adapter
validation step, not a carry fix, range proof, or production-security claim.
"""

from .crypto import (ProtocolError, aggregate_commitments, digest,
                     pedersen_verify_opening, verify)
from .source_paper_numeric import paper_codec, recover
from .source_profiles import key_sum_valid, update_codec

MODE = "aggregate-key-opening-replay-v1"


class AggregateValidationError(ProtocolError):
    """Closed public failure categories; never include key/coordinate values."""

    CODES = frozenset({"history-unverified", "model-unverified", "selection-mismatch"})

    def __init__(self, code, message):
        if code not in self.CODES:
            raise ValueError("unknown aggregate validation category")
        self.code = code
        super().__init__(message)


def enabled(manifest):
    if "aggregation_validation" not in manifest:
        return False
    profile = manifest["aggregation_validation"]
    if not isinstance(profile, dict) or profile.get("kind") != MODE:
        raise ProtocolError("unsupported source aggregation validation profile")
    from .aion_source_selection import enabled as selection_enabled
    from .aion_source_sharing import enabled as sharing_enabled
    from .aion_source_roster import enabled as roster_enabled
    if (not selection_enabled(manifest) or not sharing_enabled(manifest)
            or not roster_enabled(manifest) or "paper_numerics" not in manifest):
        raise ProtocolError("source aggregate validation requires encrypted, roster-bound paper MGF")
    return True


def require_previous(manifest, state, round_id, body):
    if not enabled(manifest):
        return
    approved = state.get("source-aggregate-validation", {})
    if approved.get("round") != round_id or approved.get("value") != digest(body):
        raise AggregateValidationError("history-unverified", "source MGF history requires local aggregate validation")


def check_proposal(manifest, state, request, sequence):
    if not enabled(manifest) or sequence % 2 == 0 or sequence == 1:
        return
    round_id = request["round"]
    if sequence != 2 * round_id + 1:
        raise ProtocolError("source model BFT sequence differs from round")
    approved = state.get("source-aggregate-validation", {})
    if approved.get("round") != round_id or approved.get("value") != request["value"]:
        raise AggregateValidationError("model-unverified", "source model BFT requires local aggregate validation")


def validate(manifest, identity, state, request, hprf):
    if not enabled(manifest) or int(identity.name) not in manifest["committee"]:
        raise ProtocolError("only profiled source committee validates aggregates")
    if set(request) != {"action", "task", "round", "body", "opening"}:
        raise ProtocolError("invalid source aggregate validation schema")
    round_id = request["round"]
    tag = digest(request)
    saved = state.get("source-aggregate-validation", {})
    if saved.get("round") == round_id:
        if saved["request"] != tag:
            raise ProtocolError("conflicting source aggregate validation")
        return saved["response"]
    if round_id != saved.get("round", 0) + 1:
        raise ProtocolError("source aggregate validation round out of order")
    selection = state.get("source-selection", {})
    if selection.get("round") != round_id or "pending" not in selection:
        raise ProtocolError("source aggregate requires local masked selection snapshot")
    members = selection["members"]
    if state.get("source-key-releases", {}).get(str(round_id)) != digest(sorted(members)):
        raise ProtocolError("source aggregate requires locally authorized key release")
    opening = request.get("opening")
    if (not isinstance(opening, dict) or set(opening) != {"key", "blind"}
            or type(opening["key"]) is not int or type(opening["blind"]) is not int
            or not key_sum_valid(manifest, opening["key"], len(members))):
        raise ProtocolError("invalid source aggregate key opening")
    stored = state.get("shares", {})
    if any(str(member) not in stored for member in members):
        raise ProtocolError("missing pinned source key commitments")
    commitments = aggregate_commitments([stored[str(member)]["commitments"] for member in members])
    if not pedersen_verify_opening((opening["key"], opening["blind"]), commitments):
        raise ProtocolError("source aggregate opening differs from pinned selected commitments")
    codec = paper_codec(manifest, hprf, round_id, selection["previous_linf"])
    # Replay the manifest-selected recovery: legacy candidate-based or the
    # bounded transmission-centered path. Both retain raw Y for actual history.
    decoded, numeric = recover(manifest, {}, codec, hprf, round_id,
                               selection["pending"], opening["key"])
    scale = update_codec(manifest, hprf).scale
    mean = [x / (scale * len(members)) for x in decoded]
    previous = selection["previous_model"]
    model = [w + x for w, x in zip(previous, mean, strict=True)]
    expected = dict(msg="FINAL_SUM", iteration=round_id, task=manifest["task"],
                    final_sum=mean, model=model, paper_numeric=numeric)
    body = request.get("body")
    if not isinstance(body, dict) or digest(body) != digest(expected):
        raise ProtocolError("source aggregate model or numeric history differs from local replay")
    response = dict(value=digest(expected), verified=True)
    response["authorization"] = identity.sign(dict(msg="MASKED_MGF_AGGREGATE",
        task=manifest["task"], round=round_id, selected=members, parent=digest(previous),
        vectors_digest=selection["response"]["vectors_digest"], value=response["value"]))
    # Do NOT retain the key or blinding opening in public receipts/history.
    state["source-aggregate-validation"] = dict(round=round_id, request=tag,
        value=response["value"], response=response)
    return response


def check_validations(manifest, receipts, round_id, members, body, *, parent, vectors_digest=None):
    if not isinstance(receipts, list) or len(receipts) != len(manifest["committee"]):
        raise ProtocolError("incomplete source aggregate validations")
    seen, tags = set(), set()
    expected = {"msg", "task", "round", "selected", "parent", "vectors_digest", "value"}
    for receipt in receipts:
        statement = verify(receipt, manifest["source_transport_registry"])
        sender = receipt["sender"]
        if (sender not in {str(i) for i in manifest["committee"]} or sender in seen
                or not isinstance(statement, dict) or set(statement) != expected
                or statement["msg"] != "MASKED_MGF_AGGREGATE"
                or statement["task"] != manifest["task"]
                or type(statement["round"]) is not int or statement["round"] != round_id
                or statement["selected"] != members or statement["parent"] != parent
                or statement["value"] != digest(body)
                or (vectors_digest is not None and statement["vectors_digest"] != vectors_digest)):
            raise ProtocolError("source aggregate validation context mismatch")
        seen.add(sender)
        tags.add(statement["vectors_digest"])
    if len(tags) != 1:
        raise ProtocolError("source aggregate validation vectors disagree")

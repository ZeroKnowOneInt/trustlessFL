"""Committee authorization of a selected masked-MGF cohort.

This adds transport authentication and deterministic filter replay, not a
solution for scaled-HPRF carry, private key-domain attacks, or CCS. Historical
aggregate metadata is trusted only after its existing normal-path BFT commit;
that certificate does not prove that the metadata itself was computed honestly.
"""

from fractions import Fraction

from .aion_source_cohort import round_clients
from .crypto import ProtocolError, digest, verify
from .source_paper_numeric import descriptor, paper_codec, select_masked

MODE = "signed-masked-filter-replay-v1"


def enabled(manifest):
    return manifest.get("selection_authorization", {}).get("kind") == MODE


def sign_vector(manifest, identity, vector):
    body = {**vector, "task": manifest["task"]}
    return {**body, "signature": identity.sign(body)["signature"]}


def check_vectors(manifest, vectors, round_id, parent, codec, max_integer):
    allowed = {"msg", "iteration", "sender", "masked_vector", "parent",
               "paper_scale", "task", "signature"}
    cohort = round_clients(manifest, round_id)
    if (not isinstance(vectors, list) or len(vectors) != len(cohort)
            or any(not isinstance(v, dict) or set(v) != allowed
                   or type(v.get("sender")) is not int for v in vectors)
            or {v["sender"] for v in vectors} != set(cohort)):
        raise ProtocolError("invalid signed source VECTOR cohort")
    from .paper_dmc import round_even
    limit = max_integer * (codec.denominator // 10 ** codec.decimals)
    upper = limit + round_even(codec.coefficient * codec.modulus) + 1
    for vector in vectors:
        if (vector["task"] != manifest["task"] or vector["msg"] != "VECTOR"
                or type(vector["iteration"]) is not int or vector["iteration"] != round_id
                or vector["parent"] != parent or vector["paper_scale"] != descriptor(codec)
                or not isinstance(vector["masked_vector"], list)
                or len(vector["masked_vector"]) != manifest["dimension"]
                or any(type(x) is not int or not -limit <= x <= upper
                       for x in vector["masked_vector"])):
            raise ProtocolError("signed source VECTOR context or numeric bounds mismatch")
        unsigned = {k: v for k, v in vector.items() if k != "signature"}
        verify(dict(sender=str(vector["sender"]), body=unsigned, signature=vector["signature"]),
               manifest["source_transport_registry"], sender=str(vector["sender"]))


def check_authorizations(manifest, authorizations, round_id, members, bound, *, parent=None, vectors_digest=None):
    """Check signed replay receipts; not an independent numeric aggregate proof."""
    if not isinstance(authorizations, list) or len(authorizations) != len(manifest["committee"]):
        raise ProtocolError("incomplete source selection authorizations")
    seen, vector_tags = set(), set()
    expected = {"msg", "task", "round", "selected", "bound", "vectors_digest", "parent"}
    for envelope in authorizations:
        body = verify(envelope, manifest["source_transport_registry"])
        sender = envelope["sender"]
        if (sender not in {str(i) for i in manifest["committee"]} or sender in seen
                or not isinstance(body, dict) or set(body) != expected
                or body["msg"] != "MASKED_MGF_SELECTION" or body["task"] != manifest["task"]
                or type(body["round"]) is not int or body["round"] != round_id
                or body["selected"] != members or body["bound"] != bound
                or (parent is not None and body["parent"] != parent)
                or (vectors_digest is not None and body["vectors_digest"] != vectors_digest)):
            raise ProtocolError("source signed selection authorization context mismatch")
        seen.add(sender)
        vector_tags.add(body["vectors_digest"])
    if len(vector_tags) != 1:
        raise ProtocolError("source selection authorization vectors disagree")


def authorize(manifest, identity, state, request, vectors, hprf, max_integer):
    """Replay masked MGF using committed history, before releasing key shares."""
    round_id = request["round"]
    tag = digest(request)
    saved = state.get("source-selection", {})
    if saved.get("round") == round_id:
        if saved["request"] != tag:
            raise ProtocolError("conflicting source selection authorization")
        return saved["response"]
    if round_id != saved.get("round", 0) + 1:
        raise ProtocolError("source selection authorization round out of order")
    previous = request["model"]
    if (not isinstance(previous, dict) or previous.get("round") != round_id - 1
            or not isinstance(previous.get("model"), list)
            or len(previous["model"]) != manifest["dimension"]):
        raise ProtocolError("invalid source selection parent model")
    registry = state.get("source-bft", {}).get("registry")
    if registry is None:
        raise ProtocolError("source selection requires locally pinned BFT registry")
    from .aion_source_bft import check_source_commit
    history = dict(paper_terms=list(saved.get("paper_terms", [])))
    if round_id == 1:
        if any(type(x) not in (int, float) or x != 0 for x in previous["model"]):
            raise ProtocolError("source selection genesis must be zero offset")
        value = digest(dict(msg="VALID_CLIENTS", iteration=0, valid_clients=manifest["clients"]))
        linf = None
    else:
        body = previous.get("body", {})
        if (body.get("msg") != "FINAL_SUM" or body.get("iteration") != round_id - 1
                or body.get("task") != manifest["task"] or body.get("model") != previous["model"]):
            raise ProtocolError("source selection history differs from committed model")
        value = digest(body)
        meta = body.get("paper_numeric", {})
        try:
            linf, bound, term = (Fraction(meta[k]) for k in ("next_linf", "bound", "history_term"))
            if linf <= 0 or bound < 0 or term < 0:
                raise ValueError("invalid history magnitude")
        except (KeyError, TypeError, ValueError, ZeroDivisionError) as exc:
            raise ProtocolError("invalid source selection MGF history") from exc
        history.update(paper_bound=str(bound), paper_terms=(history["paper_terms"] + [str(term)])[-2:])
    check_source_commit(manifest, previous["commit"], registry, 2 * (round_id - 1) + 1, value)
    codec = paper_codec(manifest, hprf, round_id, linf)
    check_vectors(manifest, vectors, round_id, digest(previous["model"]), codec, max_integer)
    # Arrival order is not trusted. Ties must match the aggregator's canonical
    # sender order, otherwise an untrusted relay could choose tied survivors.
    vectors = sorted(vectors, key=lambda v: v["sender"])
    pending = select_masked(manifest, history, codec, vectors, round_id)
    if request["members"] != pending["selected"]:
        raise ProtocolError("source key request differs from masked MGF selection")
    response = dict(selected=pending["selected"], bound=pending["bound"],
                    vectors_digest=digest(vectors))
    response["authorization"] = identity.sign(dict(msg="MASKED_MGF_SELECTION",
        task=manifest["task"], round=round_id, parent=digest(previous["model"]), **response))
    state["source-selection"] = dict(round=round_id, request=tag, response=response,
        paper_terms=history["paper_terms"], members=pending["selected"])
    return response

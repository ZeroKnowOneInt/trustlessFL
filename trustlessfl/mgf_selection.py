"""Deterministic artifact-style rank selection over signed masked probes.

The first three rounds use the artifact's percentile bootstrap. The optional
artifact-bound path uses certified full-cohort mask norms and two historical
aggregate norms. Legacy percentile tasks retain bounded-MGF evolution.
"""

from .crypto import ProtocolError, digest, verify
from .numeric import MGFIntegerCodec


def artifact_selection_bound(p, registry, state, norm_certificate, probes, parent, round_id):
    from .protocol import check_certificate
    from .mgf_wire import _decimal, _nonnegative_decimal
    if not isinstance(norm_certificate, dict):
        raise ProtocolError("missing cohort mask norm certificate")
    body = check_certificate(norm_certificate, p, registry)
    norm = _nonnegative_decimal(body.get("mask_linf"), "cohort mask norm")
    if body != p.claim("mgf-cohort-norm", round_id, parent=parent,
                       candidates=digest(probes), mask_linf=body["mask_linf"]):
        raise ProtocolError("cohort mask norm certificate differs from candidates")
    if round_id <= 3:
        return state["bound"]
    if len(state["norms"]) != 2:
        raise ProtocolError("artifact MGF lacks two historical norms")
    denominator = (_nonnegative_decimal(state["norms"][0], "historical norm")
                   + _nonnegative_decimal(state["mask_linf"], "historical mask norm"))
    if denominator <= 0:
        raise ProtocolError("artifact MGF bound denominator is zero")
    bound = ((_nonnegative_decimal(state["norms"][1], "historical norm") + norm)
             / denominator * _nonnegative_decimal(state["bound"], "historical bound"))
    return _decimal(bound) if bound else "0"


def admission_bound(p, state):
    return str(p.max_abs * (p.mgf_dimension + 1)) if p.mgf_percentile else state["bound"]


def check_probe(p, registry, probe, parent, round_id):
    if not isinstance(probe, dict) or probe.get("sender") not in p.clients:
        raise ProtocolError("invalid MGF probe author")
    body = verify(probe, registry, sender=probe["sender"])
    if not isinstance(body, dict):
        raise ProtocolError("invalid MGF probe body")
    vector, update = body.get("vector"), body.get("update")
    expected = p.claim("mgf-probe", round_id, parent=parent, vector=vector, update=update)
    if "key_material" in body:
        expected["key_material"] = body["key_material"]
    if (body != expected or not isinstance(update, str) or len(update) != 64
            or any(c not in "0123456789abcdef" for c in update)
            or not isinstance(vector, list) or len(vector) != p.mgf_dimension
            or not p.mgf_codec.accepts(vector, str(p.max_abs * (p.mgf_dimension + 1)))):
        raise ProtocolError("invalid signed MGF probe")
    return body


def select_probes(p, registry, probes, parent, round_id, bound):
    if not isinstance(probes, list) or not 2 <= len(probes) <= len(p.clients):
        raise ProtocolError("invalid MGF candidate count")
    names = [probe.get("sender") for probe in probes if isinstance(probe, dict)]
    if len(names) != len(probes) or any(not isinstance(name, str) for name in names):
        raise ProtocolError("invalid MGF candidate identity")
    if names != [name for name in p.clients if name in set(names)]:
        raise ProtocolError("MGF candidates must be unique and in manifest order")
    bodies = [check_probe(p, registry, probe, parent, round_id) for probe in probes]
    squares = [sum(value * value for value in body["vector"]) for body in bodies]
    order = sorted(range(len(probes)), key=lambda index: squares[index])
    minimum = max(2, len(probes) // 10)
    maximum = max(minimum, 4 * len(probes) // 5)
    if round_id <= 3:
        threshold = squares[order[len(probes) // 10]]
        rank = sum(value < threshold for value in squares)
        recorded_bound = {"squared_integer": threshold}
    else:
        fraction = MGFIntegerCodec._fraction(bound)
        if fraction < 0:
            raise ProtocolError("invalid percentile MGF bound")
        rank = sum(value * fraction.denominator**2 < (fraction.numerator * p.mgf_codec.scale)**2
                   for value in squares)
        recorded_bound = {"decimal": bound}
    retained = max(minimum, min(maximum, rank))
    selected = {names[index] for index in order[:retained]}
    return [name for name in p.clients if name in selected], {
        "round": round_id, "cohort": names, "squared_norms": squares,
        "bound": recorded_bound, "selected_count": retained,
        "small_cohort_floor_override": len(probes) // 10 < 2,
    }


def check_update_probe(p, registry, body):
    probe = body.get("mgf_probe")
    claim = check_probe(p, registry, probe, body["parent"], body["round"])
    unsigned = {key: value for key, value in body.items() if key != "mgf_probe"}
    if claim["update"] != digest(unsigned) or claim["vector"] != body.get("mgf_vector"):
        raise ProtocolError("MGF probe is not bound to the signed update")
    if "key_material" in claim and claim["key_material"] != {
            "commitments": body["mgf"]["key_commitments"],
            "packets": body["mgf"]["key_packets"]}:
        raise ProtocolError("MGF probe key material differs from update")
    return probe

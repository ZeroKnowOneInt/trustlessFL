"""Experimental single-view paper-scale adapter for the source Flower path.

Original HPRF scalar keys are unchanged; sharing is selected by the manifest.
Quantized-lift removal is a conditional
numeric adaptation, not the author's literal Algorithm 8 or a security proof.
"""

from fractions import Fraction
from numbers import Integral

from .aion_source_cohort import round_clients
from .crypto import ProtocolError
from .paper_dmc import PaperDMC, evolve_bound, public_mgf_term, round_even
from .source_profiles import (CENTERED, TransmissionCodec, ProfiledLegacyCodec,
                              centered_codec, profile, profile_tag)

FILTER_RULE = "inclusive-historical-bound-v1"
LEGACY_FILTER_RULE = "e2-ranked-minmax-v1"
SUM_SCALE_SOURCE = "quantized-sum"
LEGACY_SCALE_SOURCE = "quantized-mean"


def mgf_scope(manifest):
    """Missing scope is the historical projection adaptation, NOT full norm."""
    scope = manifest.get("source_profile", {}).get("mgf_scope", "projection")
    if scope not in ("projection", "full-vector"):
        raise ProtocolError("unsupported source MGF scope")
    return scope


def scope_span(manifest):
    return (0, manifest["dimension"]) if mgf_scope(manifest) == "full-vector" else tuple(
        manifest["paper_numerics"]["projection"])


def require_scope_history(manifest, state):
    if (state.get("paper_terms") or "paper_bound" in state) and state.get(
            "paper_mgf_scope", "projection") != mgf_scope(manifest):
        raise ProtocolError("source MGF history scope mismatch")


def integer_square_sum(values):
    # Convert BEFORE multiplication: np.int64 * np.int64 can silently wrap.
    if any(not isinstance(x, Integral) or isinstance(x, bool) for x in values):
        raise ProtocolError("MGF requires integer transmission coordinates")
    return sum(int(x) * int(x) for x in values)


def history_statistics(manifest, codec, values, mask_total, masks, count):
    """Current actual-mask-SUM history, in the declared norm scope/units.

    Full-vector changes the coordinates, not actual-mask-sum to paper-hprf.
    values is the recovered model-unit SUM, not an unmasked client vector.
    """
    start, stop = scope_span(manifest)
    units = scale_source(manifest)
    historical_update = values if units == SUM_SCALE_SOURCE else [x / count for x in values]
    next_linf = max(abs(x) for x in historical_update[start:stop])
    if next_linf <= 0 and not (isinstance(codec, TransmissionCodec)
            and profile(manifest)["period_policy"] == "fixed-integer"):
        raise ProtocolError("paper MGF next scale is zero")
    mask_linf = Fraction(max(mask_total[start:stop]), codec.denominator)
    modular_mask_linf = codec.coefficient * max(masks[start:stop]) / codec.denominator
    term = public_mgf_term(historical_update[start:stop], [0] * (stop - start), codec) + mask_linf
    return next_linf, mask_linf, modular_mask_linf, term


def scale_source(manifest):
    """Missing profiles retain historical mean/mask-SUM adapter semantics."""
    if manifest["paper_numerics"].get("wire_encoding", "decimal") != "decimal":
        raise ProtocolError("unsupported source precision; exact-scale wire is publicly invertible")
    source = manifest["paper_numerics"].get("scale_source", LEGACY_SCALE_SOURCE)
    if source not in (SUM_SCALE_SOURCE, LEGACY_SCALE_SOURCE):
        raise ProtocolError("unsupported source scale units")
    return source


class MGFSelectionError(ProtocolError):
    """Public-safe rejection of a cohort too small for aggregate release."""

    CODES = frozenset({"insufficient-valid"})

    def __init__(self, code):
        if code not in self.CODES:
            raise ValueError("unknown MGF selection failure category")
        self.code = code
        super().__init__("paper MGF has fewer than two in-bound clients")


def filter_rule(manifest):
    rule = manifest["paper_numerics"].get("filter_rule", LEGACY_FILTER_RULE)
    if rule not in (FILTER_RULE, LEGACY_FILTER_RULE):
        raise ProtocolError("unknown source paper MGF filter rule")
    return rule


def paper_codec(manifest, hprf, round_id, linf=None):
    filter_rule(manifest)
    options = manifest["paper_numerics"]
    scale_source(manifest)
    if options.get("wire_encoding", "decimal") != "decimal":
        raise ProtocolError("unsupported source precision; exact-scale wire is publicly invertible")
    count = len(round_clients(manifest, round_id))
    if count < 20:
        raise ProtocolError("paper-scale E2 bootstrap needs >=20 candidates for two survivors")
    if profile(manifest)["recovery"] == CENTERED:
        return centered_codec(manifest, hprf, count, linf)
    magnitude = options["initial_linf"] if linf is None else linf
    codec = PaperDMC(count, manifest["decimals"], hprf.p).with_mgf(
        magnitude, beta=options["beta"], hmax_domain="normalized")
    if "source_profile" in manifest:
        return ProfiledLegacyCodec(codec.clients, codec.decimals, codec.modulus,
                                   codec.coefficient, profile_tag(manifest))
    return codec


def descriptor(codec):
    if isinstance(codec, TransmissionCodec):
        return dict(recovery=CENTERED, S=codec.scale, d=codec.spacing,
                    M=codec.transmission_period, nmax=codec.max_clients,
                    C=str(codec.real_bound), rounding="nearest-even", aggregation="unweighted",
                    coefficient=str(codec.coefficient), denominator=codec.denominator,
                    candidates=codec.clients, profile_digest=codec.binding)
    result = dict(coefficient=str(codec.coefficient), denominator=codec.denominator,
                  model_decimals=codec.decimals, candidates=codec.clients)
    if getattr(codec, "binding", None) is not None:
        result["profile_digest"] = codec.binding
    return result


def mask_integer_wire(codec, encoded, masks):
    if isinstance(codec, TransmissionCodec):
        return codec.mask(encoded, masks)
    if len(encoded) != len(masks):
        raise ProtocolError("paper integer wire dimension mismatch")
    if any(type(x) is not int for x in encoded) or any(
            type(h) is not int or not 0 <= h <= codec.modulus for h in masks):
        raise ProtocolError("invalid paper integer wire input")
    extra = codec.denominator // 10 ** codec.decimals
    return [x * extra + round_even(codec.coefficient * h)
            for x, h in zip(encoded, masks, strict=True)]


def selection_statistics(manifest, state, codec, vectors, round_id):
    """Exact scores and the existing bootstrap/history threshold; no selection.

    Diagnostics also remain available if the inclusive selection would abort.
    This does not substitute a public/unmasked vector for Y.
    """
    require_scope_history(manifest, state)
    start, stop = scope_span(manifest)
    names = [v["sender"] for v in vectors]
    squares = [integer_square_sum(v["masked_vector"][start:stop]) for v in vectors]
    order = sorted(range(len(names)), key=lambda i: squares[i])
    minimum, maximum = len(names) // 10, 4 * len(names) // 5
    if minimum < 2:
        raise ProtocolError("paper MGF requires at least two selected clients")
    if round_id <= 3:
        threshold = squares[order[minimum]]
        rank = sum(value < threshold for value in squares)
        # E2 percentile bootstrap; subsequent TWO historical terms follow
        # the paper, not E2's current-cohort norm oracle.
        row = vectors[order[minimum]]["masked_vector"][start:stop]
        bound = public_mgf_term([Fraction(x, codec.denominator) for x in row], [0] * len(row), codec)
    else:
        terms = state.get("paper_terms", [])
        if len(terms) != 2:
            raise ProtocolError("missing paper MGF historical terms")
        bound = evolve_bound(state["paper_bound"], older_term=terms[0], newer_term=terms[1])
        rank = sum(Fraction(value, codec.denominator**2) <= bound**2 for value in squares)
    return dict(names=names, squares=squares, order=order, minimum=minimum,
                maximum=maximum, bound=bound, rank=rank)


def select_masked(manifest, state, codec, vectors, round_id):
    policy = filter_rule(manifest)
    scores = selection_statistics(manifest, state, codec, vectors, round_id)
    names, squares, order, minimum, maximum, bound, rank = (
        scores[k] for k in ("names", "squares", "order", "minimum", "maximum", "bound", "rank"))
    if round_id > 3 and policy == FILTER_RULE:
        # Algorithm 6's inclusive bound, not E2's ranked min/max override.
        # A privacy minimum is a reason to abort, never to admit bad inputs.
        if rank < 2:
            raise MGFSelectionError("insufficient-valid")
        count = rank
    else:
        # Explicit compatibility/initialization: first three rounds still use
        # the declared E2 percentile bootstrap, not a paper bootstrap claim.
        count = max(minimum, min(maximum, rank))
    selected = [names[i] for i in order[:count]]
    if isinstance(codec, TransmissionCodec) and count > codec.max_clients:
        raise ProtocolError("selected clients exceed transmission nmax")
    total = [sum(int(vectors[i]["masked_vector"][j]) for i in order[:count])
             for j in range(manifest["dimension"])]
    result = dict(round=round_id, selected=selected, total=total, bound=float(bound),
                  bound_decimal=str(bound), paper_scale=descriptor(codec))
    if "mgf_scope" in manifest.get("source_profile", {}):
        result["mgf_scope"] = mgf_scope(manifest)
    return result


def recover(manifest, state, codec, hprf, round_id, pending, seed_sum):
    require_scope_history(manifest, state)
    if pending.get("mgf_scope", "projection") != mgf_scope(manifest):
        raise ProtocolError("source recovery MGF scope differs from selection")
    centered = isinstance(codec, TransmissionCodec)
    if centered != (profile(manifest)["recovery"] == CENTERED):
        raise ProtocolError("recovery codec differs from manifest source profile")
    if "source_profile" in manifest and getattr(codec, "binding", None) != profile_tag(manifest):
        raise ProtocolError("recovery codec task binding changed")
    masks = hprf.hprf(seed_sum, round_id, manifest["dimension"])
    count = len(pending["selected"])
    scale = codec.scale if centered else 10 ** manifest["decimals"]
    if centered:
        if pending.get("paper_scale") != descriptor(codec):
            raise ProtocolError("transmission recovery profile differs from selected vectors")
        encoded_sum = codec.recover(pending["total"], masks, count)
        values = [Fraction(x, scale) for x in encoded_sum]
    else:
        values = codec.remove_quantized_lift(
            [Fraction(x, codec.denominator) for x in pending["total"]], masks,
            selected_count=count, decimal_wire=True)
        encoded_sum = [int(x * scale) for x in values]
    # Once the selected SUM has been uniquely decoded, its exact DECIMAL-WIRE
    # mask sum is already available as Y_sum-X_sum. No new sharing/messages or
    # individual plaintext updates are necessary. Do not replace this lift
    # with H(sum_key) mod p when computing the experimental history norm.
    extra = codec.denominator // scale
    mask_total = [y - x * extra for y, x in zip(pending["total"], encoded_sum, strict=True)]
    limit = count * round_even(codec.coefficient * hprf.p)
    if any(x < 0 or x > limit for x in mask_total):
        raise ProtocolError("recovered selected mask sum outside decimal-wire bounds")
    # Algorithm 6's x_r is the selected SUM. The optimizer still consumes
    # its mean, but that mean must not silently replace the protocol SUM.
    units = scale_source(manifest)
    next_linf, mask_linf, modular_mask_linf, term = history_statistics(
        manifest, codec, values, mask_total, masks, count)
    metadata = dict(scale=descriptor(codec), next_linf=str(next_linf), selected_count=count,
                    bound=pending["bound_decimal"], history_term=str(term),
                    removal=CENTERED if centered else "conditional-quantized-lift", aggregate="selected-mean",
                    mask_linf=str(mask_linf), modular_mask_linf=str(modular_mask_linf),
                    mask_norm_source=("recovered-selected-transmission-mask-sum" if centered
                                      else "recovered-selected-decimal-mask-sum"))
    if "filter_rule" in manifest["paper_numerics"]:
        metadata["filter_rule"] = filter_rule(manifest)
    if "scale_source" in manifest["paper_numerics"]:
        metadata.update(scale_source=units, history_aggregate=(
            "selected-sum" if units == SUM_SCALE_SOURCE else "legacy-mean-update-mask-sum"))
    if "source_profile" in manifest:
        metadata["source_profile"] = profile(manifest)
    if "mgf_scope" in manifest.get("source_profile", {}):
        metadata["mgf_scope"] = mgf_scope(manifest)
    return encoded_sum, metadata

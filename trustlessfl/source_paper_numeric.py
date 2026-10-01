"""Experimental single-view paper-scale adapter for the source Flower path.

Original HPRF scalar keys are unchanged; sharing is selected by the manifest.
Quantized-lift removal is a conditional
numeric adaptation, not the author's literal Algorithm 8 or a security proof.
"""

from fractions import Fraction

from .aion_source_cohort import round_clients
from .crypto import ProtocolError
from .paper_dmc import PaperDMC, evolve_bound, public_mgf_term, round_even


def paper_codec(manifest, hprf, round_id, linf=None):
    options = manifest["paper_numerics"]
    if options.get("wire_encoding", "decimal") != "decimal" or options.get(
            "scale_source", "quantized-mean") != "quantized-mean":
        raise ProtocolError("unsupported source precision; exact-scale wire is publicly invertible")
    count = len(round_clients(manifest, round_id))
    if count < 20:
        raise ProtocolError("paper-scale E2 bootstrap needs >=20 candidates for two survivors")
    magnitude = options["initial_linf"] if linf is None else linf
    return PaperDMC(count, manifest["decimals"], hprf.p).with_mgf(
        magnitude, beta=options["beta"], hmax_domain="normalized")


def descriptor(codec):
    return dict(coefficient=str(codec.coefficient), denominator=codec.denominator,
                model_decimals=codec.decimals, candidates=codec.clients)


def mask_integer_wire(codec, encoded, masks):
    if len(encoded) != len(masks):
        raise ProtocolError("paper integer wire dimension mismatch")
    if any(type(x) is not int for x in encoded) or any(
            type(h) is not int or not 0 <= h <= codec.modulus for h in masks):
        raise ProtocolError("invalid paper integer wire input")
    extra = codec.denominator // 10 ** codec.decimals
    return [x * extra + round_even(codec.coefficient * h)
            for x, h in zip(encoded, masks, strict=True)]


def select_masked(manifest, state, codec, vectors, round_id):
    start, stop = manifest["paper_numerics"]["projection"]
    names = [v["sender"] for v in vectors]
    squares = [sum(x * x for x in v["masked_vector"][start:stop]) for v in vectors]
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
    count = max(minimum, min(maximum, rank))
    selected = [names[i] for i in order[:count]]
    total = [sum(vectors[i]["masked_vector"][j] for i in order[:count])
             for j in range(manifest["dimension"])]
    return dict(round=round_id, selected=selected, total=total, bound=float(bound),
                bound_decimal=str(bound), paper_scale=descriptor(codec))


def recover(manifest, state, codec, hprf, round_id, pending, seed_sum):
    masks = hprf.hprf(seed_sum, round_id, manifest["dimension"])
    count, scale = len(pending["selected"]), 10 ** manifest["decimals"]
    values = codec.remove_quantized_lift(
        [Fraction(x, codec.denominator) for x in pending["total"]], masks,
        selected_count=count, decimal_wire=True)
    means = [x / count for x in values]
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
    start, stop = manifest["paper_numerics"]["projection"]
    next_linf = max(abs(x) for x in means[start:stop])
    if next_linf <= 0:
        raise ProtocolError("paper MGF next scale is zero")
    mask_linf = Fraction(max(mask_total[start:stop]), codec.denominator)
    modular_mask_linf = codec.coefficient * max(masks[start:stop]) / codec.denominator
    term = public_mgf_term(means[start:stop], [0] * (stop - start), codec) + mask_linf
    metadata = dict(scale=descriptor(codec), next_linf=str(next_linf), selected_count=count,
                    bound=pending["bound_decimal"], history_term=str(term),
                    removal="conditional-quantized-lift", aggregate="selected-mean",
                    mask_linf=str(mask_linf), modular_mask_linf=str(modular_mask_linf),
                    mask_norm_source="recovered-selected-decimal-mask-sum")
    return encoded_sum, metadata

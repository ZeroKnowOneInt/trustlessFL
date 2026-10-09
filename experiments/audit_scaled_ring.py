"""Public-fixture audit of consistent scaled-ring arithmetic.

This is not a Flower run, range proof, or private MGF completion. The audit
uses original HPRF outputs, fixed public fixture keys and independently chosen
bounded test updates. No runtime secrets or experiment client files are read.
"""

import argparse
import hashlib
import json
import random
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.paper_dmc import PaperDMC, rational, round_even, select_masked


def audit_public_history(run):
    """Check the centered-range premise against already PUBLIC round sums.

    These post-hoc sums cannot be used to manufacture a pre-decode bound.
    We neither read node state/keys nor verify the learning result here: use
    verify_source_learning for that. Hashes identify the inspected evidence.
    """
    from trustlessfl.source_paper_numeric import paper_codec, descriptor

    run = Path(run)
    manifest_bytes = (run / "manifest.json").read_bytes()
    result_bytes = (run / "results.json").read_bytes()
    manifest, result = json.loads(manifest_bytes), json.loads(result_bytes)
    if not manifest.get("paper_numerics") or not result.get("history"):
        raise ValueError("public paper-scale history required")
    source = Path(manifest["source-root"]) / "agent/Aion/HPRF"
    for name in ("initialization_values", "matrix"):
        expected = manifest["source-sha256"][f"agent/Aion/HPRF/{name}"]
        if hashlib.sha256((source / name).read_bytes()).hexdigest() != expected:
            raise ValueError("public history HPRF source hash differs")
    hprf = OriginalAionHPRF.from_directory(source)
    previous_linf = None
    rows = []
    for expected_round, event in enumerate(result["history"], 1):
        if event["round"] != expected_round:
            raise ValueError("public history round order differs")
        codec = paper_codec(manifest, hprf, expected_round, previous_linf)
        numeric = event["paper_numeric"]
        if numeric["scale"] != descriptor(codec):
            raise ValueError("public history scale differs from original HPRF profile")
        count = len(event["selected"])
        if not 1 <= count <= codec.clients or len(event["result"]) != manifest["dimension"]:
            raise ValueError("public history dimensions differ")
        # Public result is the selected mean, whereas the lift is for a SUM.
        sums = [rational(v) * count for v in event["result"]]
        quantized = [codec.quantize(v) for v in sums]
        if any(abs(a - b) > Fraction(1, 10**12) for a, b in zip(sums, quantized)):
            raise ValueError("public sum is not consistent with model quantization")
        error_bound = (codec.coefficient * (count - 1) + Fraction(count, 2)) / codec.denominator
        centered = [codec.quantize((v + codec.period / 2) % codec.period - codec.period / 2)
                    for v in quantized]
        rows.append(dict(round=expected_round, selected_count=count,
                         sum_linf=str(max(abs(v) for v in quantized)),
                         scaled_modulus=str(codec.period), half_period=str(codec.period / 2),
                         worst_case_decimal_error=str(error_bound),
                         observed_sum_fits_centered_range=all(
                             abs(v) + error_bound < codec.period / 2 for v in quantized),
                         public_sum_changed_by_centering=sum(
                             a != b for a, b in zip(centered, quantized))))
        previous_linf = numeric["next_linf"]
    return dict(scope="read-only public history range check, not a new decode rule or replay",
                run=str(run), public_input_sha256={
                    "manifest.json": hashlib.sha256(manifest_bytes).hexdigest(),
                    "results.json": hashlib.sha256(result_bytes).hexdigest()},
                rounds=rows, individual_keys_read=False,
                plaintext_used_for_runtime_decoding=False)


def audit(source, *, rounds=10, clients=20, dimension=32):
    if (any(type(v) is not int for v in (rounds, clients, dimension))
            or rounds < 1 or clients < 2 or dimension < 1):
        raise ValueError("positive rounds/dimension and at least two clients required")
    source = Path(source)
    hprf = OriginalAionHPRF.from_directory(source)
    codec = PaperDMC(clients, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    # This is an explicit synthetic precondition, NOT a bound inferred from
    # MGF, the previous model, or observed private training updates.
    bound = codec.period / 4
    scale = 10 ** codec.decimals
    per_client_quanta = int(bound * scale / (2 * clients))
    rng = random.Random(20261002)
    keys = [rng.randint(1, 100000) for _ in range(clients)]
    verified = {"exact": 0, "decimal": 0}
    carry_coordinates = 0
    max_error = 0
    first_norm = None
    for round_id in range(1, rounds + 1):
        masks = [hprf.hprf(k, round_id, dimension) for k in keys]
        models = [[Fraction(rng.randint(-per_client_quanta, per_client_quanta), scale)
                   for _ in range(dimension)] for _ in keys]
        subsets = [list(range(clients)), list(range(0, clients, 2)),
                   list(range(round_id % clients, clients))]
        for members in subsets:
            aggregate = hprf.hprf(sum(keys[i] for i in members), round_id, dimension)
            expected = [sum((models[i][j] for i in members), Fraction(0))
                        for j in range(dimension)]
            assert all(abs(x) <= bound for x in expected)
            for j, h in enumerate(aggregate):
                difference = sum(masks[i][j] for i in members) - h
                carry = round_even(Fraction(difference, hprf.p))
                error = difference - carry * hprf.p
                assert abs(error) <= len(members) - 1
                max_error = max(max_error, abs(error))
                carry_coordinates += carry != 0
            actual_mask = [codec.coefficient * sum(masks[i][j] for i in members)
                           / codec.denominator for j in range(dimension)]
            aggregate_mask = [codec.coefficient * h / codec.denominator for h in aggregate]
            if first_norm is None and max(actual_mask) != max(aggregate_mask):
                first_norm = dict(round=round_id, selected_count=len(members),
                                  actual_sum_linf=str(max(actual_mask)),
                                  aggregate_hprf_linf=str(max(aggregate_mask)))
            for name, masking in (("exact", codec.mask), ("decimal", codec.mask_decimal_wire)):
                wire = [masking(models[i], masks[i]) for i in members]
                total = [sum((v[j] for v in wire), Fraction(0)) for j in range(dimension)]
                result = codec.remove_centered(total, aggregate, sum_bound=bound,
                    selected_count=len(members), decimal_wire=name == "decimal")
                assert result == expected
                verified[name] += dimension

    # A modulo-only wire change aliases distinct, model-grid-aligned updates
    # even with EXACTLY THE SAME individual keys and key commitments.
    # This statement concerns this proposed wire transformation, not today's
    # unchanged source wire, nor arbitrary alternative cryptographic schemes.
    pair = keys[:2]
    pair_masks = [hprf.hprf(k, 1, 1) for k in pair]
    executions = []
    for models in (([Fraction(0)], [Fraction(0)]), ([codec.period], [Fraction(0)])):
        wire = [codec.mask_decimal_wire(x, h)[0]
                for x, h in zip(models, pair_masks, strict=True)]
        reduced = [v % codec.period for v in wire]
        executions.append(dict(wire=wire, reduced=reduced,
                               selected=select_masked([[v] for v in reduced], codec.period),
                               plaintext_sum=sum(x[0] for x in models)))
    assert executions[0]["reduced"] == executions[1]["reduced"]
    assert executions[0]["selected"] == executions[1]["selected"] == [0, 1]
    assert executions[0]["plaintext_sum"] != executions[1]["plaintext_sum"]
    assert executions[0]["wire"] != executions[1]["wire"]

    # Norm filtering is not preserved by reducing the client VECTOR modulo
    # period. A large positive update wraps into the small mask-sized range.
    ordinary = [codec.mask_decimal_wire([5 * codec.period], pair_masks[0]),
                codec.mask_decimal_wire([0], pair_masks[1])]
    reduced = [[v % codec.period for v in row] for row in ordinary]
    bound_mgf = 2 * codec.period
    ordinary_selection = select_masked(ordinary, bound_mgf)
    reduced_selection = select_masked(reduced, bound_mgf)
    assert ordinary_selection == [1] and reduced_selection == [0, 1]

    # MGF acceptance itself does not imply the small plaintext SUM bound used
    # in the successful fixture. Even one zero-mask input x=2*period passes
    # this bound; neither 2*period nor its centered residue zero determines
    # the correct real sum without a separate admissible-range rule.
    assert select_masked([[2 * codec.period]], bound_mgf) == [0]
    try:
        codec.remove_centered([2 * codec.period], [0], sum_bound=bound_mgf,
                              selected_count=1, decimal_wire=True)
    except ProtocolError as exc:
        range_rejection = str(exc)
    else:
        raise AssertionError("MGF-derived ambiguous range accepted")

    return dict(
        scope="offline scaled-ring numeric audit; NOT Flower, privacy, or MGF completion",
        source_sha256={name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                       for name in ("initialization_values", "matrix")},
        rounds=rounds, clients=clients, dimension=dimension, public_fixture_keys=keys,
        effective_mask_scale=str(codec.coefficient / codec.denominator),
        scaled_modulus=str(codec.period), independent_sum_bound=str(bound),
        bounded_verified_coordinates=verified, nonzero_carry_coordinates=carry_coordinates,
        max_centered_hprf_error=max_error, aggregate_mask_norm_example=first_norm,
        modulo_wire_alias=dict(
            same_individual_keys=True, same_modulo_vectors=True, same_filter_result=True,
            unwrapped_vectors_differ=True,
            plaintext_sums=[str(e["plaintext_sum"]) for e in executions],
            reduced_wire=[str(v) for v in executions[0]["reduced"]]),
        modulo_changes_mgf=dict(bound=str(bound_mgf), ordinary_selected=ordinary_selection,
                                modulo_selected=reduced_selection),
        mgf_range_rejection=range_rejection, additional_mask_shares=0,
        limitations=["Successful lifts assume an independent, enforced real SUM bound.",
                     "The fixture bound is not justified for the actual learning workload.",
                     "Modulo reduction before MGF changes Algorithm 6 norm semantics.",
                     "Neither scaled arithmetic nor this audit is an HPRF privacy proof."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion/agent/Aion/HPRF"))
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--clients", type=int, default=20)
    parser.add_argument("--dimension", type=int, default=32)
    parser.add_argument("--run", type=Path, help="Optional existing public source results; read-only range check")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source, rounds=args.rounds, clients=args.clients, dimension=args.dimension)
    if args.run is not None:
        result["public_history"] = audit_public_history(args.run)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

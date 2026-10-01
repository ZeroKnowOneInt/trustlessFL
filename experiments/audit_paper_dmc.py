"""Offline public-key numerical audit; never reads experiment client secrets."""

import argparse
import hashlib
import json
import random
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.paper_dmc import PaperDMC, round_even, select_masked


def audit(source, *, rounds=20, dimension=840, clients=10):
    if min(rounds, dimension, clients) < 1:
        raise ValueError("positive audit dimensions required")
    source = Path(source)
    hprf = OriginalAionHPRF.from_directory(source)
    rng = random.Random(20261001)
    # Public fixture keys in the author's range. Not an enrollment or VSS run.
    keys = [rng.randint(1, 100000) for _ in range(clients)]
    base = PaperDMC(clients, 6, hprf.p)
    modes = {"dmc_only": base,
             "mgf_normalized_hmax": base.with_mgf("0.1", hmax_domain="normalized"),
             "mgf_raw_hmax": base.with_mgf("0.1", hmax_domain="raw")}
    stats = {name: {"period": str(codec.period), "literal_mismatch_coordinates": 0,
                   "centered_mismatch_coordinates": 0, "centered_rejections": 0,
                   "max_literal_error": Fraction(0), "wire_coordinates": 0,
                   "plaintext_recovered_by_rounding_wire": 0} for name, codec in modes.items()}
    evidence = {"coordinates": 0, "nonzero_carry_coordinates": 0,
                "max_centered_hprf_error": 0, "first_carry": None}
    for round_id in range(1, rounds + 1):
        masks = [hprf.hprf(k, round_id, dimension) for k in keys]
        # Signed quantized inputs within the stated public bound, including
        # deterministic outliers. MGF sees only the single masked view.
        models = [[Fraction(rng.randint(-100000, 100000), 1000000)
                   for _ in range(dimension)] for _ in keys]
        models[-1] = [Fraction(2)] * dimension
        for name, codec in modes.items():
            wire = [codec.mask(x, h) for x, h in zip(models, masks, strict=True)]
            stats[name]["wire_coordinates"] += clients * dimension
            stats[name]["plaintext_recovered_by_rounding_wire"] += sum(
                codec.quantize(y) == x for vector, model in zip(wire, models, strict=True)
                for y, x in zip(vector, model, strict=True))
            selected = select_masked(wire, "4")
            # Also verify a changing subset independent of norm selection.
            subsets = [list(range(clients)), selected, list(range(round_id % clients, clients))]
            for members in subsets:
                if not members:
                    continue
                aggregate = hprf.hprf(sum(keys[i] for i in members), round_id, dimension)
                total = [sum((wire[i][j] for i in members), Fraction(0)) for j in range(dimension)]
                expected = [sum((models[i][j] for i in members), Fraction(0)) for j in range(dimension)]
                literal = codec.remove(total, aggregate)
                result = stats[name]
                result["literal_mismatch_coordinates"] += sum(a != b for a, b in zip(literal, expected))
                result["max_literal_error"] = max(result["max_literal_error"],
                    max(abs(a - b) for a, b in zip(literal, expected)))
                try:
                    centered = codec.remove_centered(total, aggregate, sum_bound=2 * len(members))
                except ProtocolError:
                    result["centered_rejections"] += 1
                else:
                    result["centered_mismatch_coordinates"] += sum(a != b for a, b in zip(centered, expected))
                if name == "dmc_only":
                    for j, agg in enumerate(aggregate):
                        difference = sum(masks[i][j] for i in members) - agg
                        carry = round_even(Fraction(difference, hprf.p))
                        error = difference - carry * hprf.p
                        evidence["coordinates"] += 1
                        evidence["nonzero_carry_coordinates"] += carry != 0
                        evidence["max_centered_hprf_error"] = max(evidence["max_centered_hprf_error"], abs(error))
                        if carry and evidence["first_carry"] is None:
                            evidence["first_carry"] = dict(round=round_id, members=members, coordinate=j,
                                raw_difference=difference, carry=carry, small_error=error)
    for result in stats.values():
        result["max_literal_error"] = str(result["max_literal_error"])
    return {"scope": "offline exact-rational public fixtures; not Flower/privacy/defense validation",
            "source_sha256": {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                              for name in ("initialization_values", "matrix")},
            "rounds": rounds, "dimension": dimension, "clients": clients, "public_keys": keys,
            "additional_mask_shares": 0, "decimals": base.decimals,
            "extra_digits": base.extra_digits, "hprf": evidence, "modes": stats}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--dimension", type=int, default=840)
    parser.add_argument("--clients", type=int, default=10)
    args = parser.parse_args()
    result = audit(args.source, rounds=args.rounds, dimension=args.dimension,
                   clients=args.clients)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

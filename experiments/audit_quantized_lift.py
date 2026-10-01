"""Test conditional no-share sum recovery on public numerical fixtures.

Optional history supplies only already PUBLIC aggregated means. It does not
load client state or training shards. This is not a resumed learning run.
"""

import argparse
import hashlib
import json
import random
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.paper_dmc import PaperDMC, rational, round_even


def profiles(history_path=None):
    result = {"bootstrap_0.1": Fraction(1, 10),
              "author_e2_bootstrap_1": Fraction(1),
              "public_decimal_0.012347": Fraction(12347, 1000000),
              "public_mean_0.012347_div_3": Fraction(12347, 3000000)}
    if history_path:
        history = json.loads(Path(history_path).read_bytes())["history"]
        for row in history:
            count = len(row["selected"])
            maximum = max(abs(rational(v)) for v in row["result"])
            # Recover the exact fixed-point SUM from its public float mean.
            integer_sum = round_even(maximum * count * 1000000)
            if abs(maximum - Fraction(integer_sum, count * 1000000)) > Fraction(1, 10**12):
                raise ValueError("public mean is not consistent with source quantization")
            if integer_sum:
                result[f"history_r{row['round']}_mean"] = Fraction(integer_sum, count * 1000000)
                result[f"history_r{row['round']}_sum"] = Fraction(integer_sum, 1000000)
    return result


def reference_profiles(manifest_path):
    """Only the pinned PUBLIC initial checkpoint; not a client-state path."""
    import numpy as np
    path = Path(manifest_path)
    manifest = json.loads(path.read_bytes())
    reference = Path(manifest["training"]["input_root"]) / "reference.npz"
    sha = hashlib.sha256(reference.read_bytes()).hexdigest()
    if sha != manifest["training"]["input_sha256"]["reference.npz"]:
        raise ValueError("public initial checkpoint hash differs from manifest")
    with np.load(reference, allow_pickle=False) as archive:
        if set(archive.files) != {"weights"}:
            raise ValueError("public checkpoint must contain only weights")
        weights = archive["weights"]
    if weights.shape != (61706,) or not np.isfinite(weights).all():
        raise ValueError("invalid public FMNIST reference shape or values")
    # Exact binary rational of the public float checkpoint. This is not an
    # arbitrary alpha perturbation to remove a collision.
    values = {"reference_full_initial_model": Fraction(float(np.max(np.abs(weights)))),
              "reference_classifier_initial_model": Fraction(float(np.max(np.abs(weights[-850:-10]))))}
    if any(value <= 0 for value in values.values()):
        raise ValueError("zero reference magnitude cannot mask updates")
    return values, dict(reference_sha256=sha,
        manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        scope="public initial model norm candidates; NOT author E2 fixed bootstrap")


def audit(source, *, rounds=20, dimension=32, history_path=None, reference_manifest=None):
    if type(rounds) is not int or rounds < 1 or type(dimension) is not int or dimension < 1:
        raise ValueError("positive audit dimensions required")
    hprf = OriginalAionHPRF.from_directory(source)
    magnitudes = profiles(history_path)
    reference_metadata = None
    if reference_manifest:
        initial, reference_metadata = reference_profiles(reference_manifest)
        magnitudes.update(initial)
    results = {}
    for profile, magnitude in magnitudes.items():
        for count in (2, 4, 10):
            codec = PaperDMC(10, 6, hprf.p).with_mgf(magnitude, hmax_domain="normalized")
            rng = random.Random(20261001)
            keys = [rng.randint(1, 100000) for _ in range(count)]
            cases = {"previous_linf": str(magnitude), "selected_count": count,
                     "verified_rounds": 0, "ambiguous_rounds": 0, "other_rejections": 0,
                     "wrong_accepted_rounds": 0, "coordinates": dimension * rounds}
            for round_id in range(1, rounds + 1):
                models = [[Fraction(rng.randint(-100000, 100000), 1000000)
                           for _ in range(dimension)] for _ in keys]
                wire = [codec.mask_decimal_wire(x, hprf.hprf(k, round_id, dimension))
                        for k, x in zip(keys, models, strict=True)]
                total = [sum(row[j] for row in wire) for j in range(dimension)]
                expected = [sum(row[j] for row in models) for j in range(dimension)]
                try:
                    actual = codec.remove_quantized_lift(total,
                        hprf.hprf(sum(keys), round_id, dimension), selected_count=count, decimal_wire=True)
                except ProtocolError as exc:
                    cases["ambiguous_rounds" if "ambiguous" in str(exc) else "other_rejections"] += 1
                else:
                    cases["verified_rounds" if actual == expected else "wrong_accepted_rounds"] += 1
            results[f"{profile}/q{count}"] = cases
    return dict(scope="conditional quantized-lift audit, not paper Algorithm 8 or Flower learning",
                additional_mask_shares=0, decimals=6, wire_extra_digits=2,
                rounds=rounds, dimension=dimension, results=results,
                reference=reference_metadata,
                public_history_sha256=hashlib.sha256(Path(history_path).read_bytes()).hexdigest()
                    if history_path else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion/agent/Aion/HPRF"))
    parser.add_argument("--public-history", type=Path)
    parser.add_argument("--reference-manifest", type=Path)
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--dimension", type=int, default=32)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source, history_path=args.public_history,
        reference_manifest=args.reference_manifest, rounds=args.rounds, dimension=args.dimension)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

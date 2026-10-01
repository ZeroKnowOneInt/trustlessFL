"""Public-wire key-search audit of the author's 1..100000 scalar-key fixture.

Never loads an actor Context, a training shard, or a VSS share. This compares
quantized numeric candidates, not every implementation of the paper's HPRF.
"""

import argparse
import json
import random
import time
from fractions import Fraction
from pathlib import Path

import numpy as np

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.paper_dmc import PaperDMC
from experiments.audit_author_scale_precision import FinitePrecisionDMC


def round_ratio(numerator, denominator):
    integer, remainder = divmod(numerator, denominator)
    return integer + (2 * remainder > denominator or
                      (2 * remainder == denominator and integer % 2 == 1))


def search_public_keys(wire, codec, hprf, round_id, *, key_max=100000, coordinates=8):
    """Use only masked integers, public matrix, grid, scale, round and key domain."""
    if (key_max < 1 or coordinates < 1 or round_id < 1 or not wire
            or codec.modulus != hprf.p or any(type(y) is not int for y in wire)):
        raise ValueError("invalid public key-search fixture")
    step = codec.denominator // 10**codec.decimals
    numerator, denominator = codec.coefficient.numerator, codec.coefficient.denominator
    candidates = list(range(1, key_max + 1))
    counts = []
    for coordinate in range(min(coordinates, len(wire))):
        multiplier = round_id + coordinate // hprf.m
        column = hprf.column_sums[coordinate % hprf.m]
        retained = []
        for key in candidates:
            h = (((key * multiplier % hprf.q) * column % hprf.q) * hprf.p + hprf.q // 2) // hprf.q
            mask = round_ratio(numerator * h, denominator)
            if (wire[coordinate] - mask) % step == 0:
                retained.append(key)
        candidates = retained
        counts.append(len(candidates))
        if len(candidates) < 2:
            break
    return candidates, counts


def recover_public_updates(wire, codec, hprf, round_id, keys):
    if len(keys) != 1:
        raise ProtocolError("public search did not uniquely recover a fixture key")
    step = codec.denominator // 10**codec.decimals
    masks = hprf.hprf(keys[0], round_id, len(wire))
    result = []
    for y, h in zip(wire, masks):
        value = y - round_ratio(codec.coefficient.numerator * h, codec.coefficient.denominator)
        if value % step:
            raise ProtocolError("recovered key does not fit the full masked vector")
        result.append(value // step)
    return result


def audit(source, *, dimension=840, fixtures=3):
    if dimension < 1 or fixtures < 1:
        raise ValueError("positive audit dimensions required")
    hprf = OriginalAionHPRF.from_directory(source)
    results = {}
    for name, fp32, extra in (("current_decimal8", False, 0),
                               ("finite_decimal16_float32", True, 8)):
        magnitude = Fraction(253, 40000)
        if fp32:
            magnitude = Fraction(float(np.float32(float(magnitude))))
        base = PaperDMC(20, 6, hprf.p).with_mgf(magnitude, hmax_domain="normalized")
        codec = FinitePrecisionDMC(20, 6, hprf.p, base.coefficient * 10**extra,
                                  transport_extra_digits=extra)
        rng = random.Random(20261001)
        cases = []
        for r in range(1, fixtures + 1):
            # Secret is used ONLY to synthesize and assess the fixture, not as
            # an argument to the attacker. No live experiment key is loaded.
            fixture_key = rng.randint(1, 100000)
            encoded = [rng.randint(-10000, 10000) for _ in range(dimension)]
            masks = hprf.hprf(fixture_key, r, dimension)
            step = codec.denominator // 10**codec.decimals
            wire = [x * step + round_ratio(codec.coefficient.numerator * h,
                    codec.coefficient.denominator) for x, h in zip(encoded, masks)]
            started = time.monotonic()
            candidates, counts = search_public_keys(wire, codec, hprf, r)
            unique = len(candidates) == 1
            recovered = recover_public_updates(wire, codec, hprf, r, candidates) if unique else []
            cases.append(dict(round=r, candidate_counts=counts, unique_key=unique,
                recovered_key_matches_fixture=unique and candidates[0] == fixture_key,
                individual_coordinates_recovered=sum(a == b for a, b in zip(recovered, encoded)),
                coordinates=dimension, attacker_seconds=time.monotonic() - started))
        results[name] = cases
    return dict(scope="public key-domain search of quantized scalar-key artifact fixtures; not all paper HPRFs",
                key_domain=[1, 100000], dimension=dimension, fixtures=fixtures,
                actor_private_state_loaded=False, vss_shares_used=False, results=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion/agent/Aion/HPRF"))
    parser.add_argument("--dimension", type=int, default=840)
    parser.add_argument("--fixtures", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source, dimension=args.dimension, fixtures=args.fixtures)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

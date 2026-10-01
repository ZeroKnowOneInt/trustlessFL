"""Measure legacy and vector Pedersen wire sizes without printing secret material.

The full-model sizes are extrapolations from sampled commitments and ciphertext
lengths, not completed full-dimensional MGF executions.
"""

import argparse
import copy
import json
from pathlib import Path

from trustlessfl.crypto import (Identity, ORDER, canonical, decrypt_pedersen_vector_shares,
                                encrypt_pedersen_share)
from trustlessfl.protocol import Parameters, _mgf_update_material


def measure(coordinates=64, target_coordinates=61706, aggregators=4):
    if coordinates < 1 or target_coordinates < coordinates or aggregators < 4:
        raise ValueError("require 1 <= sample <= target and at least four aggregators")
    p = Parameters("mgf-wire-size-measure", ("c0", "c1"),
                   tuple(f"a{i}" for i in range(aggregators)),
                   faults=(aggregators - 1) // 3, dimension=coordinates,
                   mgf_beta="0.5", mgf_initial_alpha="0.001",
                   mgf_initial_bound="10", mgf_initial_term="1")
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    material = _mgf_update_material(p, identities["c0"], registry, 17,
                                     [500] * coordinates, 1, "0.001")
    legacy = copy.deepcopy(material)
    for name in p.aggregators:
        pairs = decrypt_pedersen_vector_shares(
            material["mask_packets"][name], identities[name], task=p.task,
            sender="c0", round_id=1, commitments=material["mask_commitments"])
        legacy["mask_packets"][name] = [
            encrypt_pedersen_share(pair, registry[name]["encryption"], task=p.task,
                                    sender="c0", recipient=name, round_id=1,
                                    coordinate=index, commitments=material["mask_commitments"][index])
            for index, pair in enumerate(pairs)]
    commitment_per_coordinate = sum(
        len(canonical(row)) + 1 for row in material["mask_commitments"]) / coordinates
    legacy_per_coordinate = commitment_per_coordinate + sum(
        sum(len(canonical(packet)) + 1 for packet in legacy["mask_packets"][name]) / coordinates
        for name in p.aggregators)
    legacy_bytes, vector_bytes = len(canonical(legacy)), len(canonical(material))
    legacy_estimate = legacy_bytes + (target_coordinates - coordinates) * legacy_per_coordinate
    constant = (vector_bytes - len(canonical(material["mask_commitments"]))
                - sum(len(packet["ciphertext"]) for packet in material["mask_packets"].values()))
    # Two 256-byte field values per coordinate, plus the 16-byte GCM tag,
    # encoded as base64. Commitments remain decimal JSON in both formats.
    pair_width = 2 * ((ORDER.bit_length() + 7) // 8)
    vector_estimate = (constant + 1 + target_coordinates * commitment_per_coordinate
                       + aggregators * 4 * ((pair_width * target_coordinates + 16 + 2) // 3))
    return {"scope": "MGF material only; target sizes extrapolated, not full-model runtime results",
            "coordinates": coordinates, "target_coordinates": target_coordinates,
            "aggregators": aggregators, "threshold": p.threshold,
            "legacy_actual_bytes": legacy_bytes, "vector_actual_bytes": vector_bytes,
            "actual_reduction_fraction": 1 - vector_bytes / legacy_bytes,
            "legacy_estimate_mib": legacy_estimate / 2**20,
            "vector_estimate_mib": vector_estimate / 2**20, "payload_limit_mib": 16}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coordinates", type=int, default=64)
    parser.add_argument("--target-coordinates", type=int, default=61706)
    parser.add_argument("--aggregators", type=int, default=4)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = measure(args.coordinates, args.target_coordinates, args.aggregators)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("xb") as stream:
            stream.write(canonical(result))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

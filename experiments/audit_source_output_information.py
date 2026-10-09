"""Read-only information-flow audit of source Flower public/received artifacts.

Reads manifest/results, signed masked inbox packets and public author setup.
No node Context, private identity, VSS share, client key, training input or
reconstructed aggregate key is read. Never exports the inferred mask vector.
"""

import argparse
import hashlib
import json
import math
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.aion_source_aggregate import check_validations
from trustlessfl.aion_source_bft import check_source_commit
from trustlessfl.aion_source_roster import statement as roster_statement
from trustlessfl.aion_source_selection import check_authorizations, check_vectors
from trustlessfl.crypto import digest
from trustlessfl.paper_dmc import round_even
from trustlessfl.source_paper_numeric import paper_codec


def integer_sum_from_public_mean(values, count, scale):
    """Recover a unique integer numerator of Python's correctly rounded mean.

    Require the candidate's division to reproduce the published float, and
    both neighboring binary-float midpoints to lie strictly within half an
    integer of that candidate. Reject ambiguity, non-grid data and nonfinite
    values. This is not a way to obtain unpublished individual updates.
    """
    if type(count) is not int or count < 2 or type(scale) is not int or scale < 1:
        raise ValueError("invalid public mean scale or participant count")
    result, maximum_error = [], Fraction(0)
    for value in values:
        if type(value) not in (int, float):
            raise ValueError("public mean must be finite numerical values")
        value = float(value)
        if not math.isfinite(value):
            raise ValueError("public mean must be finite numerical values")
        exact = Fraction.from_float(value)
        scaled = exact*count*scale
        z = round_even(scaled)
        before, after = math.nextafter(value, -math.inf), math.nextafter(value, math.inf)
        if not math.isfinite(before) or not math.isfinite(after):
            raise ValueError("public mean does not uniquely identify an integer sum")
        low = (exact+Fraction.from_float(before))*count*scale/2
        high = (exact+Fraction.from_float(after))*count*scale/2
        if (not Fraction(z)-Fraction(1, 2) < low <= scaled <= high < Fraction(z)+Fraction(1, 2)
                or z/(count*scale) != value):
            raise ValueError("public mean does not uniquely identify an integer sum")
        result.append(z)
        maximum_error = max(maximum_error, abs(scaled-z))
    return result, maximum_error


def audit(root):
    root = Path(root)
    manifest = json.loads((root/"manifest.json").read_text())
    result = json.loads((root/"results.json").read_text())
    if (manifest.get("aggregation_validation", {}).get("kind") != "aggregate-key-opening-replay-v1"
            or manifest.get("paper_numerics", {}).get("scale_source") != "quantized-sum"
            or len(result["history"]) != manifest["rounds"]):
        raise ValueError("audit requires a complete profiled source paper-MGF run")
    source = Path(manifest["source-root"])
    bft_path = source/"agent/Aion/bft.py"
    if hashlib.sha256(bft_path.read_bytes()).hexdigest() != manifest["source-sha256"]["agent/Aion/bft.py"]:
        raise ValueError("public author BFT snapshot changed")
    hprf = OriginalAionHPRF.from_directory(source/"agent/Aion/HPRF")
    legal = result["legal_bft"]
    registry = legal["registry"]
    check_source_commit(manifest, legal, registry, 1,
        digest(dict(msg="VALID_CLIENTS", iteration=0, valid_clients=manifest["clients"])))
    previous, previous_linf, rounds = [0.0]*manifest["dimension"], None, []
    scale = 10**manifest["decimals"]
    max_integer = int(Fraction(str(manifest["max_abs"]))*scale)
    for r, entry in enumerate(result["history"], 1):
        if entry["round"] != r or len(entry["result"]) != manifest["dimension"]:
            raise ValueError("invalid public round or mean dimension")
        members = entry["selected"]
        if len(members) < 2 or len(set(members)) != len(members):
            raise ValueError("invalid selected cohort")
        codec = paper_codec(manifest, hprf, r, previous_linf)
        directory = root/"masked-inbox"/digest(manifest["task"])/str(manifest["aggregator"])/str(r)
        vectors = []
        for path in sorted(directory.glob("*.json")):
            vector = json.loads(path.read_text())
            if path.name != f'{vector["sender"]}-{digest(vector)}.json':
                raise ValueError("received packet filename differs from its content digest")
            vectors.append(vector)
        vectors.sort(key=lambda v: v["sender"])
        parent = digest(previous)
        # Small batches travel inline; they need not have an inbox archive.
        # Verify any existing archive completely, but do not fabricate missing
        # vectors or treat absence as evidence of no information flow.
        vector_tag = digest(vectors) if vectors else None
        if vectors:
            check_vectors(manifest, vectors, r, parent, codec, max_integer)
        check_authorizations(manifest, entry["selection_authorizations"], r, members,
            entry["bound"], parent=parent, vectors_digest=vector_tag)
        if vector_tag is None:
            vector_tag = entry["selection_authorizations"][0]["body"]["vectors_digest"]
        check_source_commit(manifest, entry["online_bft"], registry, 2*r,
                            digest(roster_statement(manifest, r, members)))
        body = dict(msg="FINAL_SUM", iteration=r, task=manifest["task"],
                    final_sum=entry["result"], model=entry["model"], paper_numeric=entry["paper_numeric"])
        check_validations(manifest, entry["aggregate_validations"], r, members, body,
                          parent=parent, vectors_digest=vector_tag)
        proof, = entry["source_bft"]
        check_source_commit(manifest, proof, registry, 2*r+1, digest(body))
        encoded, float_error = integer_sum_from_public_mean(entry["result"], len(members), scale)
        if any(abs(z) > len(members)*max_integer for z in encoded):
            raise ValueError("public inferred sum exceeds configured integer bound")
        # No K_A is read. This only checks that an actor who already knows K_A
        # would have sufficiently precise mask_sum to infer the modular carry.
        n = len(members)
        carry_error = Fraction(n+1, 2*hprf.p)+Fraction(n, 2*codec.denominator)/codec.period
        mask_evidence = dict(mask_inference_status="missing-received-vectors",
            received_vector_digest_verified=False, inferred_mask_coordinates=0,
            mask_projection_linf_matches_committed_metadata=None,
            known_aggregate_key_would_suffice_for_carry=None)
        if vectors:
            chosen = [v["masked_vector"] for v in vectors if v["sender"] in members]
            if len(chosen) != len(members):
                raise ValueError("selected signed vector missing")
            total = [sum(row[j] for row in chosen) for j in range(manifest["dimension"])]
            extra = codec.denominator//scale
            inferred_mask = [y-extra*z for y, z in zip(total, encoded, strict=True)]
            if any(x < 0 or x > len(members)*round_even(codec.coefficient*hprf.p) for x in inferred_mask):
                raise ValueError("inferred decimal mask sum exceeds the real-wire range")
            start, stop = manifest["paper_numerics"]["projection"]
            norm = Fraction(max(inferred_mask[start:stop]), codec.denominator)
            if norm != Fraction(entry["paper_numeric"]["mask_linf"]):
                raise ValueError("publicly inferred mask norm differs from committed metadata")
            mask_evidence = dict(mask_inference_status="verified-from-received-packets-and-certified-mean",
                received_vector_digest_verified=True, inferred_mask_coordinates=len(inferred_mask),
                mask_projection_linf_matches_committed_metadata=True,
                inferred_mask_projection_linf=str(norm),
                known_aggregate_key_would_suffice_for_carry=carry_error < Fraction(1, 2))
        rounds.append(dict(round=r, selected_count=n, dimension=len(encoded),
            inferred_integer_coordinates=len(encoded),
            maximum_float_error_in_integer_units=str(float_error),
            carry_inference_error_bound=str(carry_error),
            carry_precision_condition_met=carry_error < Fraction(1, 2), **mask_evidence))
        previous, previous_linf = entry["model"], entry["paper_numeric"]["next_linf"]
    return dict(scope="existing receiver-visible packets and public certified output only",
        rounds=rounds, runtime_modified=False, new_protocol_implemented=False,
        private_keys_or_shares_read=False, training_inputs_read=False,
        aggregate_key_read=False, carry_vector_exported=False,
        additional_mask_shares=result["mask_share_deliveries"],
        limitation="mask sums are inferred, not compared with private individual keys; no full key-recovery attack")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.root), indent=2))


if __name__ == "__main__":
    main()

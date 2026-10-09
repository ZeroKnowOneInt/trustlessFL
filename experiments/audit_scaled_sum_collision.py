"""Public multi-coordinate counterexample for the present aggregate decoder.

Only fixed public fixture keys are enumerated. No experiment Context, private
key or training shard is read. This is not a runtime key-search fallback and
not indistinguishability of entire signed/VSS protocol transcripts.
"""

import argparse
import hashlib
import json
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.paper_dmc import PaperDMC, QuantizedLiftError
from trustlessfl.source_paper_numeric import FILTER_RULE, mask_integer_wire, select_masked


def audit(source, *, dimension=8, max_pairs=512):
    if (type(dimension) is not int or not 2 <= dimension <= 16
            or type(max_pairs) is not int or not 2 <= max_pairs <= 4096):
        raise ValueError("bounded public fixture audit requires dimension 2..16 and pairs 2..4096")
    source = Path(source)
    hprf = OriginalAionHPRF.from_directory(source)
    codec = PaperDMC(20, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    extra, quantum_scale = codec.denominator // 10**codec.decimals, 10**codec.decimals
    sum_key, round_id, buckets, collision, examined = 20001, 4, {}, None, 0
    for first_key in range(1, max_pairs + 1):
        keys = (first_key, sum_key - first_key)
        masks = [mask_integer_wire(codec, [0] * dimension, hprf.hprf(k, round_id, dimension)) for k in keys]
        total = [sum(row[j] for row in masks) for j in range(dimension)]
        # Model updates are multiples of extra wire units. Only public mask
        # rounding residues are compared to construct a numerical fixture.
        fingerprint = tuple(value % extra for value in total)
        current = dict(keys=keys, masks=masks, total=total)
        earlier = buckets.get(fingerprint)
        examined += 1
        if earlier is not None and earlier["total"] != total:
            collision = (earlier, current)
            break
        buckets.setdefault(fingerprint, current)
    if collision is None:
        raise ValueError("no public multi-coordinate fixture collision within audit budget")

    base = 3 * codec.period
    assert (base * codec.denominator).denominator == 1
    target = [max(a, b) + int(base * codec.denominator)
              for a, b in zip(collision[0]["total"], collision[1]["total"], strict=True)]
    bound = dimension * 6 * codec.period
    manifest = dict(dimension=dimension, paper_numerics=dict(
        projection=[0, dimension], filter_rule=FILTER_RULE))
    history = dict(paper_bound=str(bound), paper_terms=["1", "1"])
    executions = []
    for entry in collision:
        offsets = [y - mask for y, mask in zip(target, entry["total"], strict=True)]
        assert all(value % extra == 0 for value in offsets)
        encoded = [[value // extra for value in offsets], [0] * dimension]
        wire = [mask_integer_wire(codec, model, hprf.hprf(key, round_id, dimension))
                for key, model in zip(entry["keys"], encoded, strict=True)]
        vectors = [dict(sender=i, masked_vector=row) for i, row in enumerate(wire)]
        vectors += [dict(sender=i, masked_vector=[int(2 * bound * codec.denominator)] * dimension)
                    for i in range(2, 20)]
        pending = select_masked(manifest, history, codec, vectors, round_id)
        # This is numeric history/filter evidence, not a certified transcript.
        assert pending["selected"] == [1, 0]
        assert pending["total"] == target
        executions.append(dict(public_fixture_keys=entry["keys"], encoded_updates=encoded,
                               masked_vectors=wire, selected=pending["selected"],
                               encoded_sum=encoded[0]))
    assert executions[0]["encoded_sum"] != executions[1]["encoded_sum"]
    assert executions[0]["masked_vectors"] != executions[1]["masked_vectors"]
    aggregate = hprf.hprf(sum_key, round_id, dimension)
    try:
        codec.remove_quantized_lift([Fraction(value, codec.denominator) for value in target],
                                   aggregate, selected_count=2, decimal_wire=True)
    except QuantizedLiftError as exc:
        rejection = exc.code
    else:
        raise AssertionError("two different valid model sums were decoded as unique")
    assert rejection == "ambiguous"
    return dict(scope="multi-coordinate numeric aggregate decoder collision, not full protocol transcripts",
        source_sha256={name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                       for name in ("matrix", "initialization_values")},
        dimension=dimension, examined_public_pairs=examined, hprf_round=round_id,
        filter_phase="historical inclusive bound numeric test, no round certificate",
        model_scale=quantum_scale, wire_scale=codec.denominator, scaled_period=str(codec.period),
        bound=str(bound), executions=executions, aggregate_key=sum_key,
        masked_sum=target, aggregate_hprf=aggregate, decoder_rejection=rejection,
        same_full_masked_sum=True, same_aggregate_key=True, same_selected_set=True,
        different_plaintext_sums=True, individual_masked_vectors_identical=False,
        additional_mask_shares=0, experiment_private_inputs_read=False,
        limitation="Individual signed vectors and VSS commitments differ; no impossibility claim for all protocols")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion/agent/Aion/HPRF"))
    parser.add_argument("--dimension", type=int, default=8)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source, dimension=args.dimension)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({key: result[key] for key in ("scope", "dimension", "examined_public_pairs",
        "same_full_masked_sum", "different_plaintext_sums", "decoder_rejection")}, indent=2))


if __name__ == "__main__":
    main()

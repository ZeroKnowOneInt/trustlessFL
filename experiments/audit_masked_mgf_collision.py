"""Public fixture audit of filtering plus decimal-wire aggregate ambiguity.

This compares the numeric decoder's inputs, not complete VSS transcripts:
individual key commitments differ between the two executions. Reading/searching
individual keys is not a private aggregate-decoding solution.
"""

import argparse
import json
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.paper_dmc import PaperDMC, QuantizedLiftError
from trustlessfl.source_paper_numeric import mask_integer_wire, select_masked


def audit(source):
    hprf = OriginalAionHPRF.from_directory(source)
    codec = PaperDMC(20, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    keys = ((1, 20000), (94, 19907))
    masks = [tuple(mask_integer_wire(codec, [0], hprf.hprf(k, 1, 1))[0]
                   for k in pair) for pair in keys]
    extra = codec.denominator // 10**codec.decimals
    wire = tuple(max(a, b) for a, b in zip(*masks, strict=True))
    models = []
    selections = []
    manifest = dict(dimension=1, paper_numerics=dict(projection=[0, 1]))
    for pair, mask in zip(keys, masks, strict=True):
        offsets = [y - m for y, m in zip(wire, mask, strict=True)]
        assert all(x % extra == 0 for x in offsets)
        encoded = [x // extra for x in offsets]
        actual_wire = [mask_integer_wire(codec, [x], hprf.hprf(k, 1, 1))[0]
                       for k, x in zip(pair, encoded, strict=True)]
        assert tuple(actual_wire) == wire
        models.append(encoded)
        # Both colliding clients pass the same bootstrap norm filter. Fillers
        # establish its public percentile threshold and are identical here.
        vectors = [dict(sender=i, masked_vector=[value])
                   for i, value in enumerate(actual_wire + [3 * codec.denominator // 100] * 18)]
        selections.append(select_masked(manifest, {}, codec, vectors, 1))
    assert selections[0] == selections[1]
    assert selections[0]["selected"] == [1, 0]
    assert sum(keys[0]) == sum(keys[1])
    assert sum(models[0]) != sum(models[1])
    try:
        codec.remove_quantized_lift([Fraction(sum(wire), codec.denominator)],
            hprf.hprf(sum(keys[0]), 1, 1), selected_count=2, decimal_wire=True)
    except QuantizedLiftError as exc:
        rejection = exc.code
    else:
        raise AssertionError("ambiguous aggregate was accepted")
    assert rejection == "ambiguous"
    return dict(scope="one-coordinate decimal numeric decoder, not full VSS transcript indistinguishability",
                key_pairs=keys, encoded_updates=models, masked_wire=wire,
                model_scale=10**codec.decimals, wire_scale=codec.denominator,
                selected=selections[0]["selected"], bound=selections[0]["bound_decimal"],
                sum_key=sum(keys[0]), encoded_sums=[sum(x) for x in models],
                same_individual_masked_values=True, same_filter_result=True,
                same_aggregate_decoder_inputs=True, different_plaintext_sums=True,
                decoder_rejection=rejection, additional_mask_shares=0,
                limitation="Different individual commitments; no claim about all possible HPRFs or wire encodings")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion/agent/Aion/HPRF"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

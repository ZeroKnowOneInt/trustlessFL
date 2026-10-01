"""Check the pinned author's sharing routine against one-share privacy.

Public test secrets only. Calls the actual extracted source VSS.share method;
the attack receives one share and public degree/field, never a private actor.
"""

import argparse
import json
from pathlib import Path

from trustlessfl.aion_source_asr import load_source, source_inventory
from trustlessfl.crypto import MODULUS


def recover_from_one_fixed_share(share, threshold, prime):
    index, value, _blind = map(int, share)
    public_tail = sum(degree * pow(index, degree, prime)
                      for degree in range(1, threshold))
    return (value - public_tail) % prime


def audit(source):
    inventory = source_inventory(source)
    _, _, VSS, _ = load_source(str(source), json.dumps(inventory, sort_keys=True))
    rows = []
    for threshold in (2, 3, 4):
        for secret in (1, 937, 100000):
            vss = VSS.__new__(VSS)
            # Public test generators suffice to exercise share generation;
            # no claim is made about Pedersen group security/verification.
            vss.p, vss.g, vss.h = MODULUS, 2, 3
            shares, _ = vss.share(secret, 6, threshold, MODULUS)
            recovered = [recover_from_one_fixed_share(s, threshold, MODULUS) for s in shares]
            assert recovered == [secret] * 6
            rows.append(dict(threshold=threshold, fixture_secret=secret,
                             shares_tested=6, one_share_recovered=6))
    return dict(scope="author VSS fixed polynomial coefficients; public fixtures only",
                source_sha256=inventory, fixtures=rows,
                one_share_recoveries=sum(r["one_share_recovered"] for r in rows),
                threshold_privacy=False,
                limitation="Does not evaluate other VSS implementations or prove end-to-end MGF feasibility")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(dict(one_share_recoveries=result["one_share_recoveries"],
                         threshold_privacy=result["threshold_privacy"])))


if __name__ == "__main__":
    main()

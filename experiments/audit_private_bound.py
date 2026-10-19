"""Explicit plaintext no-wrap audit. No private live runtime is implemented."""
import argparse
from dataclasses import replace
import json
from pathlib import Path
import random

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.private_bound import (
    NoWrapPolicy, ReferenceSubmission, aggregate, scale_canonical_mask,
)


def audit(seed=20261010):
    rng = random.Random(seed)
    p = NoWrapPolicy(16, 20, 10**6, 10000, 21, 840000021, 16*10**12)
    # Actual repository adapter, controlled public matrix; not production PRF security.
    modulus = 14760426300877770769
    hprf = OriginalAionHPRF(1,16,modulus,5*modulus,[[j+1 for j in range(16)]])
    cases = 0
    profiles = []
    for M in (1, 15, 840000021, 2**128):
        for d in (1,21):
            current = replace(p, mask_max=M, spacing=d)
            for round_id in range(1,26):
                updates = [tuple(rng.randint(-p.coordinate_cap,p.coordinate_cap)
                                 for _ in range(p.dimension)) for _ in range(p.max_clients)]
                rows = []
                for update in updates:
                    key = rng.randrange(hprf.q)
                    h = hprf.hprf(key, round_id, p.dimension)
                    masks = tuple(scale_canonical_mask(value % hprf.p,hprf.p,M) for value in h)
                    rows.append(ReferenceSubmission(current.encode(update,masks),masks))
                result = aggregate(current,rows,mode="plaintext-reference")
                expected = tuple(sum(row[j] for row in updates) for j in range(p.dimension))
                assert result == dict(status="ok",sum=expected,count=p.max_clients)
                cases += p.dimension*p.max_clients
            profiles.append(dict(M=M,d=d,widths=current.widths()))
    return dict(scope="plaintext arithmetic with original HPRF adapter; no MPC/privacy/FL-performance claim",
                seed=seed,coordinate_cases=cases,profiles=profiles,passed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    result = audit()
    body = json.dumps(result,indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(body+'\n',encoding='utf-8')
    print(body)


if __name__ == '__main__':
    main()

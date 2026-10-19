"""Offline counterexamples to the proposed filtered-sum functionality.

No native MPC, network, training, or transport tests. Masks are synthetic test
inputs. A perfectly secure MPC would reveal exactly the same public outputs.
"""
import argparse
from dataclasses import replace
from fractions import Fraction
import hashlib
import json
from pathlib import Path

from trustlessfl.private_bound import (
    DynamicBound, NoWrapPolicy, PublicRound, ReferenceSubmission, aggregate,
)

ROOT = Path(__file__).resolve().parents[1]


def policy(*, clients=4, threshold=25, minimum=2, output="sum-and-count"):
    return NoWrapPolicy(1, clients, 10, 1, 21, 15, threshold, minimum, output)


def evaluate(updates, p=None):
    p = p or policy()
    rows = [ReferenceSubmission(p.encode([u], [i % (p.mask_max+1)]),
                                (i % (p.mask_max+1),))
            for i, u in enumerate(updates)]
    return aggregate(p, rows, mode="plaintext-reference")


def isolation():
    # IDs 0,1 collude. Two honest clients enter, but only one survives.
    a = [0, 0, 3, 6]
    b = [0, 0, 1, 8]
    result_a, result_b = evaluate(a), evaluate(b)
    assert sum(a[2:]) == sum(b[2:]) == 9
    assert result_a == dict(status="ok", sum=(3,), count=3)
    assert result_b == dict(status="ok", sum=(1,), count=3)
    assert result_a["sum"][0] - sum(a[:2]) == a[2]
    return dict(id="selected-honest-isolation", severity="blocking-output-policy",
        colluding_clients=2, input_honest_clients=2, selected_honest_clients=1,
        world_a=a, world_b=b, unfiltered_honest_sum=9,
        public_a=result_a, public_b=result_b, recovered_accepted_honest_update=3,
        identity_linkage="additional knowledge of which honest client passes is needed to label the vector",
        same_unfiltered_sum_but_distinguishable=True)


def threshold_requery():
    u = [0, 0, 3, 6]
    high = evaluate(u, policy(threshold=36))
    low = evaluate(u, policy(threshold=9))
    recovered = [low["sum"][0], high["sum"][0]-low["sum"][0]]
    assert recovered == u[2:]
    return dict(id="threshold-requery", severity="blocking-session-policy",
        assumption="same frozen honest updates queried twice with different thresholds",
        public_high=high, public_low=low, recovered_honest_update_values=recovered,
        identity_linkage="vector values are recovered; their assignment to the two honest identities needs extra information")


def cohort_requery():
    # Each release contains >=2 honest contributors. Differencing still isolates.
    full = evaluate([0, 1, 2, 3], policy(threshold=100))
    subset = evaluate([0, 2, 3], policy(threshold=100))
    recovered = full["sum"][0]-subset["sum"][0]
    assert recovered == 1
    return dict(id="overlapping-cohort-requery", severity="blocking-session-policy",
        assumption="same frozen honest updates reused in overlapping cohorts",
        public_full=full, public_subset=subset, recovered_honest_update=recovered,
        honest_contributors_per_release=[3, 2])


def mean_only():
    # Both worlds have the same UNFILTERED honest sum 18 and same count 3.
    # RoundEven does lose precision; multiplying a rounded mean by count does
    # NOT recover a general exact sum. We prove distinguishability instead.
    p = replace(policy(threshold=64, output="mean-only"), coordinate_cap=20)
    a, b = [0, 0, 6, 12], [0, 0, 3, 15]
    public_a, public_b = evaluate(a, p), evaluate(b, p)
    assert sum(a[2:]) == sum(b[2:]) == 18
    assert public_a == dict(status="ok", mean=(2,))
    assert public_b == dict(status="ok", mean=(1,))
    return dict(id="mean-only-not-a-general-repair", severity="output-policy",
        world_a=a, world_b=b, unfiltered_honest_sum=18,
        public_a=public_a, public_b=public_b,
        same_unfiltered_sum_but_distinguishable=True,
        limitation="rounded mean does not generally reveal an exact individual update; it still leaks more than the unfiltered sum")


def minimum_guard():
    # This is a mathematical bound, NOT an implemented admission/collusion proof.
    cases = 0
    for q in range(2, 31):
        for t in range(q-1):
            required = t+2
            for accepted in range(q+1):
                worst_honest = max(0, accepted-t)
                assert (accepted >= required) == (worst_honest >= 2)
                cases += 1
    guarded = policy(minimum=4)
    excluded = evaluate([0, 0, 3, 6], guarded)
    all_pass = evaluate([0, 0, 4, 5], guarded)
    assert excluded == dict(status="abort")
    assert all_pass == dict(status="ok", sum=(9,), count=4)
    return dict(id="honest-quorum-and-abort-leak", severity="output-contract",
        counting_cases=cases, necessary_count="accepted >= upper_bound_colluding_clients + 2",
        q_minus_two_corruption_requires_all_q_pass=True,
        same_unfiltered_honest_sum=9, public_a=excluded, public_b=all_pass,
        abort_status_still_input_dependent=True,
        limitation="ensures two honest contributions under the stated bound; not DP or original ideal-functionality equivalence")


def dynamic_capture():
    p = policy(threshold=100)
    dynamic = DynamicBound(100, 1, 100)
    before = evaluate([10, 10, 10, 10], p)
    cancellation = evaluate([-10, -10, 10, 10], p)
    assert before["sum"] == (40,) and cancellation["sum"] == (0,)
    history = [PublicRound(1, (10,), 100), PublicRound(2, (0,), 100)]
    threshold = dynamic.next_threshold(p, history)
    captured = evaluate([0, 0, 10, 10], replace(p, squared_bound=threshold))
    assert threshold == 25
    assert captured == dict(status="ok", sum=(0,), count=2)
    # A third successful output is all-corrupt zero; the boundary remains low.
    next_threshold = dynamic.next_threshold(p, [history[1], PublicRound(3, (0,), threshold)])
    assert next_threshold == threshold
    return dict(id="dynamic-boundary-cancellation-capture", severity="blocking-robustness-claim",
        successful_initial_output=before, poisoned_output=cancellation,
        threshold_before=100, threshold_after=threshold,
        next_output=captured, selected_honest_clients=0, next_threshold=next_threshold,
        masks_and_wrap_errors=0, poisoned_updates_within_current_boundary=True)


def benign_cancellation():
    p = policy(threshold=100)
    dynamic = DynamicBound(100, 1, 100)
    first = evaluate([10, 10, 10, 10], p)
    second = evaluate([10, -10, 10, -10], p)
    history = [PublicRound(1, (10,), 100), PublicRound(2, (0,), 100)]
    threshold = dynamic.next_threshold(p, history)
    third = evaluate([10, -10, 10, -10], replace(p, squared_bound=threshold))
    assert first["status"] == second["status"] == "ok"
    assert threshold == 25 and third == dict(status="abort")
    assert dynamic.next_threshold(p, history) == 25
    return dict(id="benign-heterogeneity-abort-lock", severity="robustness-liveness",
        synthetic_not_observed_fmnist_event=True, malicious_clients=0,
        first_output=first, second_output=second, next_threshold=threshold,
        third_output=third, unchanged_history_keeps_abort_threshold=True)


def direction_poison():
    p = policy(clients=20, threshold=1)
    u = [-1]*18 + [1, 1]
    result = evaluate(u, p)
    assert result == dict(status="ok", sum=(-16,), count=20)
    return dict(id="in-bound-direction-poison", severity="robustness-limit",
        q=20, colluding_clients=18, squared_norm_every_client=1,
        honest_update_direction=1, public_output=result,
        accepted_attack_reverses_sum=True,
        limitation="synthetic sign-flip, not an empirical backdoor or FMNIST attack")


def history_authentication():
    p = policy(threshold=100)
    dynamic = DynamicBound(100, 1, 100)
    certified_example = [PublicRound(1, (10,), 100), PublicRound(2, (10,), 100)]
    fabricated = [PublicRound(1, (10,), 100), PublicRound(2, (0,), 100)]
    honest_t = dynamic.next_threshold(p, certified_example)
    fabricated_t = dynamic.next_threshold(p, fabricated)
    assert honest_t == 100 and fabricated_t == 25
    return dict(id="history-authentication-is-external", severity="missing-integration-invariant",
        legitimate_history_threshold=honest_t, fabricated_history_threshold=fabricated_t,
        certificate_verified_by_reference=False,
        limitation="helper deliberately trusts its caller; not a cryptographic signature forgery")


def public_small_mask():
    p = replace(policy(threshold=100), mask_max=1)
    recovered = 0
    for u in range(-p.coordinate_cap, p.coordinate_cap+1):
        for mask in (0, 1):
            public_y = p.encode([u], [mask])[0]-p.spacing*p.coordinate_cap
            assert public_y//p.spacing == u
            recovered += 1
    return dict(id="small-M-requires-private-raw-input", severity="conditional-integration-risk",
        mask_max=1, spacing=p.spacing, coordinates_recovered_without_key=recovered,
        formula="floor(Y/d) = u when Y=d*u+m and 0<=m<d",
        assumption="raw Y or offset mistakenly sent publicly; proposed private input path does not do this")


def wire_audit():
    # Independent direct integer oracle, including EVERY small-profile wire word.
    checks = 0
    for M in (1, 15, 840000021, 2**128):
        for d in (1, 21):
            p = replace(policy(), mask_max=M, spacing=d)
            zero = ReferenceSubmission(p.encode([0], [0]), (0,))
            bits = p.widths()["offset_unsigned"]
            for mask in sorted({0, M//2, M}):
                values = (range(1 << bits) if M <= 15 else sorted({0, 1, p.offset_max,
                    p.offset_max+1, (1 << bits)-1, *[p.encode([u], [mask])[0] for u in range(-10, 11)]}))
                for v in values:
                    residual = v - d*p.coordinate_cap - mask
                    valid = (v <= p.offset_max and residual % d == 0
                        and abs(residual) <= d*p.coordinate_cap
                        and (residual//d)**2 <= p.squared_bound)
                    result = aggregate(p, [zero, zero, ReferenceSubmission((v,), (mask,))],
                                       mode="plaintext-reference")
                    expected = dict(status="ok", count=2+int(valid),
                                    sum=((residual//d if valid else 0),))
                    assert result == expected, (M, d, mask, v, result, expected)
                    checks += 1
    return dict(id="arithmetic-wire-and-range-audit", severity="no-failure-found-in-tested-domain",
        independent_oracle_checks=checks, M_profiles=[1,15,840000021,str(2**128)],
        spacings=[1,21], small_profiles_exhaust_all_wire_words=True,
        large_profiles="valid updates plus wire-boundary samples", all_equal=True,
        limitation="plaintext integer semantics; no native field implementation or general security proof")


def audit():
    cases = [check() for check in (isolation, threshold_requery, cohort_requery,
        mean_only, minimum_guard, dynamic_capture, benign_cancellation,
        direction_poison, history_authentication, public_small_mask, wire_audit)]
    paths = ["trustlessfl/private_bound.py", "mpc/Programs/Source/aion_private_bound.mpc",
             "experiments/audit_private_bound_security.py"]
    return dict(scope="offline output-policy and integer counterexamples; ideal MPC assumed correct",
        native_mpc_run=False, training_run=False, tls_testing=False,
        assertions_passed=True, security_approved=False,
        note="passing assertions reproduce vulnerabilities; they do not certify security",
        source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in paths},
        cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit()
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text+"\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()

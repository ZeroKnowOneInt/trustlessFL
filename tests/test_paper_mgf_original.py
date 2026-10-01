"""Client-side original HPRF masks; no plaintext classifier side channel."""

from dataclasses import replace
from pathlib import Path

import numpy as np
import pytest

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import Identity
from trustlessfl.protocol import Parameters, Party, certificate, check_finalized_model
from trustlessfl.crypto import ProtocolError
from trustlessfl.mgf_wire import check_mgf_aggregate_mask
from trustlessfl.numeric import MGFIntegerCodec


@pytest.fixture
def parameters():
    source = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not source.exists():
        pytest.skip("author artifact required")
    setup = OriginalAionHPRF.from_directory(source).public_setup()
    return Parameters("paper-client-mgf", ("c0", "c1", "c2"), ("a0", "a1", "a2", "a3"),
        dimension=2, decimals=3, max_abs=10, mask_backend="aion-original",
        original_hprf_setup=setup, mgf_beta="0.2", mgf_initial_alpha="0.2",
        mgf_initial_bound="2", mgf_initial_term="1")


def test_original_ring_scaled_masks_and_carry(parameters):
    """Scaling a smaller author ring by 2**128 silently erases the mask."""
    p = parameters.codec.output_modulus
    codec = parameters.mgf_codec
    h = 3 * p // 4
    masked, masks = codec.mask([0.3, -0.1], [h, h], "0.2")
    assert masks == [150, 150]
    assert masked == [450, 50]
    # Two bounded masks are summed as integers; HPRF sums in Z_p.
    total = [2 * value for value in masks]
    aggregate = [(2 * h) % p] * 2
    check_mgf_aggregate_mask(total, aggregate, "0.2", 2, codec.scale, modulus=p)
    assert codec.recover([900, 100], total, 2, alpha="0.2") == [600, -200]
    with pytest.raises(ProtocolError, match="inconsistent"):
        check_mgf_aggregate_mask(total, aggregate, "0.2", 2, codec.scale)
    with pytest.raises(ProtocolError, match="inconsistent"):
        check_mgf_aggregate_mask([320, 300], aggregate, "0.2", 2, codec.scale, modulus=p)
    with pytest.raises(ProtocolError, match="HPRF output"):
        codec.mask([0.3, -0.1], [p, h], "0.2")


def test_postaggregate_norm_retains_integer_mask_carry(parameters):
    from fractions import Fraction
    from trustlessfl.mgf_wire import evolve_mgf_state, initial_mgf_state
    p = parameters.codec.output_modulus
    individual = 3 * p // 4
    _, masks = parameters.mgf_codec.mask([0, 0], [individual, individual], "0.2")
    actual = [2 * value for value in masks]
    hsum = [(2 * individual) % p] * 2
    state = initial_mgf_state(parameters)
    corrected = evolve_mgf_state(parameters, state, [600, 800], 2, hsum, aggregate_mask=actual)
    modular_reference = evolve_mgf_state(parameters, state, [600, 800], 2, hsum)
    # Public selected mean norm 0.5 + exact bounded mask sum norm 0.3.
    assert Fraction(corrected["term"]) == Fraction(4, 5)
    assert Fraction(modular_reference["term"]) < Fraction(corrected["term"])
    with pytest.raises(ProtocolError, match="inconsistent"):
        evolve_mgf_state(parameters, state, [600, 800], 2, hsum, aggregate_mask=[320, 300])


def test_mask_sum_norm_is_explicit_and_bound_into_task_configuration(parameters):
    from dataclasses import asdict
    legacy = asdict(parameters)
    legacy.pop("mgf_mask_sum_norm")
    assert Parameters.from_dict(legacy).config_digest == parameters.config_digest
    corrected = replace(parameters, mgf_mask_sum_norm=True)
    assert corrected.config_digest != parameters.config_digest


def test_count_alpha_is_not_always_a_bound_after_decimal_mask_rounding(parameters):
    from fractions import Fraction
    from trustlessfl.numeric import MGFIntegerCodec
    modulus = parameters.codec.output_modulus
    codec = MGFIntegerCodec(decimals=3, max_abs=10, max_clients=3, hprf_modulus=modulus)
    # A 0.0006 mask near the maximum rounds to 0.001 on the wire.
    _, mask = codec.mask([0], [modulus - 1], "0.0006")
    actual_three_masks = Fraction(3 * mask[0], codec.scale)
    assert actual_three_masks == Fraction(3, 1000)
    assert actual_three_masks > 3 * Fraction("0.0006")


def test_protocol_mask_sum_norm_reuses_existing_material(parameters, monkeypatch):
    import trustlessfl.protocol as protocol
    from trustlessfl.mgf_wire import evolve_mgf_state
    corrected = replace(parameters, mgf_mask_sum_norm=True)
    identities = {name: Identity.generate(name) for name in corrected.clients + corrected.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, corrected, registry, trainer=lambda *_: [0.1, 0.0])
               for name, identity in identities.items()}
    enrollments = [parties[c].enroll({}) for c in corrected.clients]
    model = certificate(parties["a0"].initialize({"enrollments": enrollments})["body"],
        [parties[a].initialize({"enrollments": enrollments}) for a in corrected.aggregators], corrected, registry)
    updates = [parties[c].train({"model": model}) for c in corrected.clients]
    roster = certificate(parties["a0"].prepare({"model": model, "updates": updates})["body"],
        [parties[a].prepare({"model": model, "updates": updates}) for a in corrected.aggregators], corrected, registry)
    shares = [parties[a].share({"roster": roster}) for a in corrected.aggregators]
    observed = []
    def checked(*args, **kwargs):
        assert kwargs.get("aggregate_mask") is not None
        observed.append(kwargs["aggregate_mask"])
        return evolve_mgf_state(*args, **kwargs)
    monkeypatch.setattr(protocol, "evolve_mgf_state", checked)
    votes = [parties[a].finalize({"roster": roster, "shares": shares}) for a in corrected.aggregators]
    assert len(observed) == 4 and all(value == observed[0] for value in observed)
    certificate(votes[0]["body"], votes, corrected, registry)


@pytest.mark.parametrize("modulus", [0, 1, True, "101"])
def test_invalid_mgf_output_ring(modulus):
    with pytest.raises(ProtocolError, match="modulus"):
        MGFIntegerCodec(hprf_modulus=modulus)


def test_single_view_is_committed_and_old_digest_is_preserved(parameters):
    from dataclasses import asdict
    legacy = asdict(parameters)
    legacy.pop("mgf_single_view")
    assert Parameters.from_dict(legacy).config_digest == parameters.config_digest
    with pytest.raises(ProtocolError, match="requires a projection"):
        replace(parameters, mgf_single_view=True)
    projected = replace(parameters, dimension=4, mgf_projection=(1, 3))
    assert replace(projected, mgf_single_view=True).config_digest != projected.config_digest


def test_duplicate_view_can_reveal_a_quantized_coordinate(parameters):
    """No raw field is needed to recover this example from the two views."""
    from fractions import Fraction
    p = parameters.codec.output_modulus
    h = 3 * p // 4
    y, _ = parameters.mgf_codec.mask([0.3], [h], "0.2")
    modular = (300 * parameters.codec.padding + h) % p
    amplitude = Fraction("0.2") * parameters.mgf_codec.scale
    estimated_mask = parameters.mgf_codec._round_ratio(
        amplitude.numerator * modular, amplitude.denominator * p)
    assert y[0] - estimated_mask == 300


def test_original_sum_key_does_not_determine_bounded_mask_sum(parameters):
    """Actual author setup: integer lift cannot be inferred from a sum key.

    These are public synthetic keys, not cached client secrets. Two possible
    executions even have the same masked sum and key sum but different true
    update sums. Removing mask shares is therefore not just an optimization
    of the current bounded-wire decoder.
    """
    hprf = OriginalAionHPRF.from_public_setup(parameters.original_hprf_setup)
    codec = parameters.mgf_codec

    def mask_sum(keys):
        masks = [hprf.hprf(key, 1, 1)[0] % hprf.p for key in keys]
        return sum(codec.mask([0.0, 0.0], masks, "0.2")[1])

    first, second = (1, 19), (4, 16)
    assert sum(first) == sum(second) == 20
    first_masks, second_masks = mask_sum(first), mask_sum(second)
    assert (first_masks, second_masks) == (41, 241)
    difference = second_masks - first_masks
    # Both plaintext possibilities are permitted by the current input bound.
    first_plaintext = parameters.codec.encode([difference / codec.scale])[0]
    second_plaintext = parameters.codec.encode([0.0])[0]
    assert first_plaintext + first_masks == second_plaintext + second_masks
    assert first_plaintext != second_plaintext
    aggregate_mask = codec.mask([0.0],
        [hprf.hprf(20, 1, 1)[0] % hprf.p], "0.2")[1][0]
    assert aggregate_mask == first_masks
    assert abs(second_masks - aggregate_mask) > 2  # Not ±1 rounding noise.


def test_reused_sum_keys_expose_client_key_for_nested_selected_rosters():
    """A minimum roster size of two does not prevent key differencing.

    CCS/group constraints would have to forbid such a release pattern; this
    synthetic example is not a claim about all possible CCS policies.
    """
    keys = {"c0": 101, "c1": 202, "c2": 303}
    first_roster = ("c0", "c1", "c2")
    second_roster = ("c0", "c1")
    released = [sum(keys[name] for name in roster)
                for roster in (first_roster, second_roster)]
    assert min(len(first_roster), len(second_roster)) >= 2
    recovered = released[0] - released[1]
    assert recovered == keys["c2"]


def test_original_cohort_mask_norm_uses_author_ring(parameters, monkeypatch):
    from fractions import Fraction
    from trustlessfl.crypto import digest
    from trustlessfl.mgf_wire import _decimal
    import trustlessfl.protocol as protocol

    p = replace(parameters, clients=("c0", "c1"), dimension=4, mgf_projection=(1, 3),
                mgf_percentile=True, mgf_artifact_bound=True)
    keys = iter([101, 202])
    monkeypatch.setattr(protocol, "_mgf_new_key", lambda _: next(keys))
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, p, registry, trainer=lambda *_: [0.1] * 4)
               for name, identity in identities.items()}
    enrollments = [parties[c].enroll({}) for c in p.clients]
    votes = [parties[a].initialize({"enrollments": enrollments}) for a in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    updates = [parties[c].train({"model": model}) for c in p.clients]
    probes = [u["body"]["mgf_probe"] for u in updates]
    request = {"model": model, "mgf_candidates": probes}
    votes = [parties[a].mgf_cohort_vote(request) for a in p.aggregators]
    request["cohort_certificate"] = certificate(votes[0]["body"], votes, p, registry)
    shares = [parties[a].mgf_cohort_share(request) for a in p.aggregators]
    votes = [parties[a].mgf_cohort_norm({**request, "cohort_shares": shares})
             for a in p.aggregators]
    mask = p.codec._mask(303, p.task, 1, p.dimension)[p.mgf_slice]
    expected = _decimal(Fraction(p.mgf_initial_alpha) * max(mask) / p.codec.output_modulus)
    proof = certificate(votes[0]["body"], votes, p, registry)
    assert proof["body"]["mask_linf"] == expected
    assert proof["body"]["candidates"] == digest(probes)


@pytest.mark.parametrize("projection,single_view", [(False, False), (True, False), (True, True)])
def test_original_client_masks_filter_and_restore_selected_sum(parameters, projection, single_view):
    p = replace(parameters, dimension=4, mgf_projection=(1, 3), mgf_single_view=single_view) if projection else parameters
    deltas = [[0.3, -0.1], [0.2, 0.1], [8.0, 8.0]]
    if projection:
        deltas = [[0.7, *delta, 0.9] for delta in deltas]
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, p, registry,
        trainer=lambda _w, i, _lr, _r: deltas[i]) for name, identity in identities.items()}
    enrollments = [parties[c].enroll({}) for c in p.clients]
    votes = [parties[a].initialize({"enrollments": enrollments}) for a in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    for round_id in (1, 2):
        updates = [parties[c].train({"model": model}) for c in p.clients]
        if single_view:
            assert all(u["body"]["vector"][p.mgf_slice] == [0, 0] for u in updates)
            bad = {**updates[0]["body"], "vector": updates[0]["body"]["vector"][:]}
            bad["vector"][1] = 1
            with pytest.raises(ProtocolError, match="duplicate masked"):
                parties["a0"].mgf_admit({"model": model, "update": identities["c0"].sign(bad)})
        for i, update in enumerate(updates):
            assert "oracle_classifier" not in update["body"]
            assert "oracle_key" not in update["body"]
            probe = update["body"]["mgf_vector" if projection else "vector"]
            assert probe != p.codec.encode(np.asarray(deltas[i])[p.mgf_slice])
        selected = [u for u in updates if p.mgf_codec.accepts(
            u["body"]["mgf_vector" if projection else "vector"], model["body"]["mgf_state"]["bound"])]
        assert [u["sender"] for u in selected] == ["c0", "c1"]
        votes = [parties[a].prepare({"model": model, "updates": selected}) for a in p.aggregators]
        roster = certificate(votes[0]["body"], votes, p, registry)
        shares = [parties[a].share({"roster": roster}) for a in p.aggregators]
        votes = [parties[a].finalize({"roster": roster, "shares": shares}) for a in p.aggregators]
        result = certificate(votes[0]["body"], votes, p, registry)
        commits = [parties[a].commit({"model": result}) for a in p.aggregators]
        result["commits"] = certificate(commits[0]["body"], commits, p, registry)
        check_finalized_model(result, p, registry)
        for a in p.aggregators:
            parties[a].decide({"model": result})
        expected = np.mean(np.asarray(deltas[:2]), axis=0) * round_id
        np.testing.assert_allclose(result["body"]["model"], expected, rtol=0, atol=1e-12)
        assert result["body"]["mgf_state"]["alpha"] == "0.05"
        model = result


@pytest.mark.parametrize("hotstuff", [False, True])
@pytest.mark.parametrize("single_view", [False, True])
@pytest.mark.parametrize("rounds", [4, 20])
def test_original_mask_mgf_flower_multiple_rounds(parameters, tmp_path, hotstuff, single_view, rounds):
    import json
    from trustlessfl.demo import provision
    from trustlessfl.local_grid import ProcessGrid
    from trustlessfl.workflow import AionWorkflow
    from trustlessfl.task import local_delta
    # This test checks repeated exact aggregation, not filter convergence.
    # Use an explicit looser bootstrap for the 20-round non-IID workload;
    # the tighter four-round setup can retain fewer than two near convergence.
    p = replace(parameters, hotstuff=hotstuff, mgf_initial_alpha="0.1",
                mgf_initial_bound="30" if rounds == 20 else "10", mgf_initial_term="0.1",
                max_abs=100 if rounds == 20 else parameters.max_abs)
    if single_view:
        p = replace(p, dimension=4, mgf_projection=(1, 3), mgf_single_view=True)
    manifest, nodes = provision(tmp_path / "identities", p)

    class InspectWire(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            replies = super().call(grid, names, action, **kwargs)
            if action == "train":
                assert all("oracle_classifier" not in u["body"] for u in replies)
                assert all(("mgf_vector" in u["body"]) == single_view for u in replies)
                if single_view:
                    assert all(u["body"]["vector"][p.mgf_slice] == [0, 0] for u in replies)
                assert all("mgf" in u["body"] for u in replies)
            return replies

    workflow = InspectWire(p, json.loads(manifest.read_text())["registry"], timeout=60)
    with ProcessGrid(nodes) as grid:
        history = workflow.run(grid, rounds)
    expected = np.zeros(p.dimension)
    assert len(history) == rounds + 1
    for r in range(1, rounds + 1):
        # An evolving norm bound may reject a benign client in later rounds.
        # Verify the certified selected mean, not an unfiltered three-client
        # mean that is only coincidentally correct in the short bootstrap.
        members = workflow.certified_rosters[r]["body"]["members"]
        assert len(members) >= 2
        total = np.sum([p.codec.encode(local_delta(expected, i, p.learning_rate))
                        for i, name in enumerate(p.clients) if name in members], axis=0)
        expected += total / (len(members) * p.codec.scale)
        np.testing.assert_allclose(history[r]["body"]["model"], expected, rtol=0, atol=1e-12)
        expected_alpha = float(p.mgf_beta) * max(abs(total[p.mgf_slice])) / (len(members) * p.codec.scale)
        assert float(history[r]["body"]["mgf_state"]["alpha"]) == pytest.approx(
            expected_alpha, rel=0, abs=5e-13)

from pathlib import Path

import pytest

pytest.importorskip("gmpy2")

from fractions import Fraction
from experiments.audit_author_scale_precision import audit, finite_precision_audit, recover_public_exact_wire
from trustlessfl.paper_dmc import PaperDMC


@pytest.fixture
def source():
    path = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not path.exists():
        pytest.skip("author matrix required")
    return path


def test_exact_scale_correct_aggregate_does_not_imply_private_inputs(source):
    report = audit(source, rounds=2, dimension=4)
    for name, row in report["results"].items():
        assert row["wrong_accepted_rounds"] == 0
        if "fp32=True/rounded-wire=False" in name:
            assert row["verified_rounds"] == 2
            assert row["keyless_individual_coordinates_recovered"] == row["keyless_attack_coordinates_tested"]
            assert row["keyless_attack_coordinates_tested"] > 0


def test_finite_rounding_candidate_checked_separately_from_exact_wire(source):
    report = finite_precision_audit(source, rounds=2, dimension=4, extra_digits=8)
    for name, row in report["results"].items():
        assert row["wrong_accepted_rounds"] == 0
        assert row["verified_rounds"] == (2 if "fp32=True" in name else 0)
    assert "not Flower learning or privacy proof" in report["scope"]


def test_public_cancellation_does_not_pick_an_ambiguous_mask_endpoint():
    codec = PaperDMC(20, 6, 101).with_mgf(Fraction(1, 10), hmax_domain="normalized")
    assert recover_public_exact_wire([Fraction(0)], codec) == [None]


def test_finite_precision_audit_rejects_invalid_precision(source):
    with pytest.raises(ValueError):
        finite_precision_audit(source, extra_digits=-1)

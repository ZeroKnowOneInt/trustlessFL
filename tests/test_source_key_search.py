from pathlib import Path

import pytest

pytest.importorskip("gmpy2")

from experiments.audit_source_key_search import audit, search_public_keys, recover_public_updates
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.aion_source_server import provision_source
from trustlessfl.crypto import ProtocolError
from trustlessfl.paper_dmc import PaperDMC


@pytest.fixture
def source():
    path = Path(__file__).resolve().parents[2] / "Aion"
    if not (path / "agent/Aion/HPRF/matrix").exists():
        pytest.skip("author matrix required")
    return path


def test_public_key_search_recovers_current_and_finite_wire_fixtures(source):
    report = audit(source / "agent/Aion/HPRF", dimension=16, fixtures=2)
    assert not report["actor_private_state_loaded"]
    assert not report["vss_shares_used"]
    for name, rows in report["results"].items():
        for row in rows:
            assert row["unique_key"] and row["recovered_key_matches_fixture"]
            assert row["individual_coordinates_recovered"] == 16
            assert row["candidate_counts"][-1] == 1
            if name == "finite_decimal16_float32":
                assert len(row["candidate_counts"]) == 1


def test_key_search_never_selects_from_ambiguous_candidates(source):
    hprf = OriginalAionHPRF.from_directory(source / "agent/Aion/HPRF")
    codec = PaperDMC(20, 6, hprf.p).with_mgf("0.006325", hmax_domain="normalized")
    with pytest.raises(ProtocolError, match="uniquely"):
        recover_public_updates([0], codec, hprf, 1, [1, 2])
    with pytest.raises(ValueError):
        search_public_keys([0], codec, hprf, 0)


def test_source_manifest_declares_original_research_key_profile(tmp_path, source):
    import json
    path, _ = provision_source(tmp_path / "port", source, clients=10, committee=4,
        dimension=8, rounds=1, workload="synthetic")
    manifest = json.loads(path.read_bytes())
    assert manifest["key_profile"] == dict(kind="author-scalar", minimum=1,
                                         maximum=100000, production_privacy=False)
    assert "no production privacy claim" in manifest["scope"]

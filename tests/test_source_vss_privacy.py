from pathlib import Path

import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")

from experiments.audit_source_vss_privacy import audit, recover_from_one_fixed_share


def test_actual_author_fixed_polynomials_reveal_secret_below_threshold():
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not (source / "agent/Aion/HPRF/matrix").is_file():
        pytest.skip("author source required")
    result = audit(source)
    assert result["one_share_recoveries"] == 54
    assert result["threshold_privacy"] is False
    assert {row["threshold"] for row in result["fixtures"]} == {2, 3, 4}


def test_legacy_flower_enrollment_reply_exposes_recoverable_individual_key(tmp_path):
    import json
    from trustlessfl.aion_source_asr import source_request
    from trustlessfl.aion_source_server import provision_source
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not (source / "agent/Aion/HPRF/matrix").is_file():
        pytest.skip("author source required")
    path, nodes = provision_source(tmp_path / "run", source, clients=10,
                                  committee=4, workload="synthetic")
    manifest = json.loads(path.read_text())
    # Historical manifests retain the source artifact behavior. Newly
    # provisioned learning tasks use encrypted randomized sharing instead.
    from trustlessfl.crypto import MODULUS
    manifest["prime"] = MODULUS
    manifest["sharing_profile"] = dict(kind="author-fixed-polynomial",
        threshold_privacy=False, flower_relay="plaintext-individual-shares")
    path.write_text(json.dumps(manifest))
    state = {}
    reply = source_request(nodes[1], state,
        dict(action="enroll", task=manifest["task"], round=1))
    event = reply["outbox"][0]
    share = event["body"]["shared_mask"]
    # Attack inputs are solely a server-visible reply and public parameters.
    recovered = recover_from_one_fixed_share(share, 2, manifest["prime"])
    assert recovered == state["mask_seed"]  # private state used only as oracle
    assert manifest["sharing_profile"] == dict(kind="author-fixed-polynomial",
        threshold_privacy=False, flower_relay="plaintext-individual-shares")

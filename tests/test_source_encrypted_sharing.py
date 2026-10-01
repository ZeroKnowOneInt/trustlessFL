import copy
import json
from pathlib import Path

import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")

from trustlessfl.aion_source_asr import source_request
from trustlessfl.aion_source_server import provision_source
from trustlessfl.aion_source_sharing import MODE, identity_for, recover_key
from trustlessfl.crypto import ORDER, ProtocolError
from experiments.audit_source_vss_privacy import recover_from_one_fixed_share


@pytest.fixture
def case(tmp_path):
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not (source / "agent/Aion/HPRF/matrix").is_file():
        pytest.skip("author source required")
    path, nodes = provision_source(tmp_path / "run", source, clients=10, committee=4,
        committee_members=[0, 1, 2, 3], workload="synthetic", rounds=4)
    manifest = json.loads(path.read_text())
    states = {actor: {} for actor in range(11)}
    def call(actor, action, **kwargs):
        return source_request(nodes[actor + 1], states[actor],
            dict(action=action, task=manifest["task"], round=1, **kwargs))
    return manifest, nodes, states, call


def test_one_time_ciphertext_relay_and_randomized_share_roundtrip(case):
    manifest, nodes, states, call = case
    assert manifest["prime"] == ORDER
    assert manifest["sharing_profile"]["kind"] == MODE
    for sender in (0, 4):
        reply = call(sender, "enroll")
        assert call(sender, "enroll") == reply
        assert len(reply["outbox"]) == 4
        for event in reply["outbox"]:
            body = event["body"]
            assert "shared_mask" not in body
            assert set(body["encrypted_share"]) == {"ephemeral", "nonce", "ciphertext"}
            recipient = event["recipient"]
            assert call(recipient, "deliver-share", body=body) == dict(received=True)
            decoded = states[recipient]["shares"][str(sender)]["shared_mask"]
            assert recover_from_one_fixed_share(decoded, 2, ORDER) != states[sender]["mask_seed"]
    entries = [dict(sender=actor, **call(actor, "sum-shares", members=[0, 4]))
               for actor in manifest["committee"]]
    assert all(set(entry) == {"sender", "sealed_sum"} for entry in entries)
    aggregator = identity_for(nodes[11], manifest)
    expected = states[0]["mask_seed"] + states[4]["mask_seed"]
    assert recover_key(manifest, aggregator, entries, [0, 4], 1) == expected
    assert recover_key(manifest, aggregator, entries[:2], [0, 4], 1) == expected
    with pytest.raises(ProtocolError, match="below threshold"):
        recover_key(manifest, aggregator, entries[:1], [0, 4], 1)
    assert not any("private" in str(value) for value in manifest["source_transport_registry"].values())
    assert all(Path(config["aion-source-identity"]).stat().st_mode & 0o777 == 0o600
               for config in nodes.values())


@pytest.mark.parametrize("change", ["recipient", "sender", "ciphertext", "commitments", "plaintext"])
def test_share_tampering_rejected_before_storage(case, change):
    manifest, _, states, call = case
    body = copy.deepcopy(call(4, "enroll")["outbox"][0]["body"])
    if change == "recipient":
        with pytest.raises(ProtocolError, match="recipient"):
            call(1, "deliver-share", body=body)
        assert "shares" not in states[1]
        return
    if change == "sender":
        body["sender"] = 5
    elif change == "ciphertext":
        raw = body["encrypted_share"]["ciphertext"]
        body["encrypted_share"]["ciphertext"] = ("00" if raw[:2] != "00" else "01") + raw[2:]
    elif change == "commitments":
        body["commitments"][0] = 1
    else:
        body["shared_mask"] = [1, 4, 2]
    with pytest.raises(ProtocolError):
        call(0, "deliver-share", body=body)
    assert "shares" not in states[0]


def test_no_singleton_or_second_subset_key_release(case):
    _, _, _, call = case
    for sender in (4, 5, 6):
        for event in call(sender, "enroll")["outbox"]:
            call(event["recipient"], "deliver-share", body=event["body"])
    with pytest.raises(ProtocolError, match="at least two"):
        call(0, "sum-shares", members=[4])
    call(0, "sum-shares", members=[4, 5])
    call(0, "sum-shares", members=[4, 5])
    with pytest.raises(ProtocolError, match="conflicting"):
        call(0, "sum-shares", members=[4, 6])


def test_pinned_identity_rejects_server_key_substitution(case):
    manifest, nodes, _, _ = case
    wrong = {**nodes[1], "aion-source-identity": nodes[2]["aion-source-identity"]}
    with pytest.raises(ProtocolError, match="identity or recipient"):
        identity_for(wrong, manifest)

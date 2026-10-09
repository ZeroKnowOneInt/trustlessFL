import copy
import json
from pathlib import Path

import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")

from trustlessfl.aion_source_asr import source_request
from trustlessfl.aion_source_server import provision_source
from trustlessfl.aion_source_sharing import (MODE, THRESHOLD_RULE, identity_for,
    recover_key, seal, threshold, open_share)
from trustlessfl.crypto import ORDER, ProtocolError, digest
from trustlessfl.aion_source_roster import statement
from experiments.audit_source_vss_privacy import recover_from_one_fixed_share


@pytest.fixture
def case(tmp_path, make_source_commit, request):
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not (source / "agent/Aion/HPRF/matrix").is_file():
        pytest.skip("author source required")
    committee_size = getattr(request, "param", 4)
    clients = max(10, committee_size)
    path, nodes = provision_source(tmp_path / "run", source, clients=clients, committee=committee_size,
        committee_members=list(range(committee_size)), workload="synthetic", rounds=4)
    manifest = json.loads(path.read_text())
    states = {actor: {} for actor in range(clients + 1)}
    proof = make_source_commit(manifest, states)
    def call(actor, action, **kwargs):
        if action == "sum-shares" and "selection_commit" not in kwargs:
            kwargs["selection_commit"] = proof(2, digest(statement(manifest, 1, kwargs["members"])))
        return source_request(nodes[actor + 1], states[actor],
            dict(action=action, task=manifest["task"], round=1, **kwargs))
    return manifest, nodes, states, call


def aggregate_entries(case):
    manifest, nodes, states, call = case
    for sender in (0, 4):
        for event in call(sender, "enroll")["outbox"]:
            call(event["recipient"], "deliver-share", body=event["body"])
    entries = [dict(sender=actor, **call(actor, "sum-shares", members=[0, 4]))
               for actor in manifest["committee"]]
    aggregator = identity_for(nodes[manifest["aggregator"] + 1], manifest)
    expected = states[0]["mask_seed"] + states[4]["mask_seed"]
    return entries, aggregator, expected


@pytest.mark.parametrize("case", [2, 3, 4, 7, 8, 10], indirect=True)
def test_fresh_threshold_matches_bft_fault_bound_and_every_share_degree(case):
    manifest, _, states, _ = case
    size = len(manifest["committee"])
    required = max(2, (size - 1) // 3 + 1)
    assert manifest["sharing_profile"]["threshold_rule"] == THRESHOLD_RULE
    assert threshold(manifest) == manifest["sharing_profile"]["threshold"] == required
    entries, aggregator, expected = aggregate_entries(case)
    assert all(len(e["sealed_sum"]["commitments"]) == required for e in entries)
    assert all(len(s["shares"]["0"]["commitments"]) == required
               for actor, s in states.items() if actor in manifest["committee"])
    for start in range(size - required + 1):
        assert recover_key(manifest, aggregator, entries[start:start + required], [0, 4], 1) == expected
    with pytest.raises(ProtocolError, match="below threshold"):
        recover_key(manifest, aggregator, entries[:required - 1], [0, 4], 1)


@pytest.mark.parametrize("size", [4, 7, 8, 10])
def test_old_threshold_rule_remains_explicit_legacy_behavior(size):
    manifest = dict(committee=list(range(size)), sharing_profile=dict(kind=MODE))
    assert threshold(manifest) == max(2, size // 3)


@pytest.mark.parametrize("field,value", [("threshold", 1), ("threshold", True),
    ("threshold", "2"), ("threshold", 3), ("threshold_rule", "unknown"),
    ("threshold_rule", None)])
def test_threshold_profile_cannot_silently_downgrade(case, field, value):
    manifest, _, _, _ = case
    manifest["sharing_profile"][field] = value
    with pytest.raises(ProtocolError, match="threshold profile"):
        threshold(manifest)


def test_bad_threshold_rejected_before_actor_state_change(case):
    from experiments.verify_source_learning import verify_learning
    manifest, nodes, _, _ = case
    manifest["sharing_profile"]["threshold"] = 1
    Path(nodes[1]["aion-source-manifest"]).write_text(json.dumps(manifest))
    state = {}
    with pytest.raises(ProtocolError, match="threshold profile"):
        source_request(nodes[1], state,
                       dict(action="enroll", task=manifest["task"], round=1))
    assert state == {}
    # No results are needed: a malformed sharing policy is rejected before
    # offline verification can accept a successful learning history.
    with pytest.raises(ProtocolError, match="threshold profile"):
        verify_learning(Path(nodes[1]["aion-source-manifest"]).parent)


@pytest.mark.parametrize("case", [4, 7], indirect=True)
@pytest.mark.parametrize("change", ["signature", "ciphertext", "members", "recipient", "pair", "foreign-commitment"])
def test_bad_aggregate_share_does_not_poison_valid_reconstruction(case, change):
    manifest, nodes, _, _ = case
    entries, aggregator, expected = aggregate_entries(case)
    damaged = copy.deepcopy(entries[0])
    body = damaged["sealed_sum"]
    if change == "signature":
        body["signature"] = "00" * 64
    elif change == "ciphertext":
        body["encrypted_share"]["ciphertext"] = "00"
    elif change == "members":
        body["members"] = [0, 5]
    elif change == "recipient":
        body["recipient"] = 1
    else:
        malicious = identity_for(nodes[body["sender"] + 1], manifest)
        if change == "pair":
            pair = open_share(manifest, aggregator, body, kind="AGGREGATE_KEY_SHARE", round_id=1)
            pair = ((pair[0] + 1) % ORDER, pair[1])
        else:
            from trustlessfl.crypto import pedersen_split
            shares, commitments = pedersen_split(111, threshold(manifest), len(manifest["committee"]))
            body["commitments"] = commitments
            pair = shares[body["index"]]
        unsigned = {k: v for k, v in body.items() if k not in {"signature", "encrypted_share"}}
        damaged["sealed_sum"] = seal(manifest, malicious, unsigned, pair)
        if change == "pair":
            with pytest.raises(ProtocolError, match="invalid randomized source VSS share"):
                open_share(manifest, aggregator, damaged["sealed_sum"],
                           kind="AGGREGATE_KEY_SHARE", round_id=1)
        else:
            assert open_share(manifest, aggregator, damaged["sealed_sum"],
                              kind="AGGREGATE_KEY_SHARE", round_id=1) == pair
    for replies in ([damaged, *entries[1:]], [*entries[1:], damaged]):
        assert recover_key(manifest, aggregator, replies, [0, 4], 1) == expected
    # Excluding bad packets still requires enough distinct valid identities.
    with pytest.raises(ProtocolError, match="below threshold"):
        recover_key(manifest, aggregator, [damaged, entries[1]], [0, 4], 1)


def test_repeated_aggregate_packets_do_not_count_as_distinct_shares(case):
    manifest, _, _, _ = case
    entries, aggregator, expected = aggregate_entries(case)
    with pytest.raises(ProtocolError, match="below threshold"):
        recover_key(manifest, aggregator, [entries[0]] * 5, [0, 4], 1)
    assert recover_key(manifest, aggregator, [entries[0]] * 5 + entries[1:], [0, 4], 1) == expected


def test_conflicting_qualified_commitment_groups_are_not_arbitrarily_selected(case):
    from trustlessfl.crypto import pedersen_split
    manifest, nodes, _, _ = case
    entries, aggregator, _ = aggregate_entries(case)
    fake_shares, fake_commitments = pedersen_split(111, 2, 4)
    forged = []
    for entry in entries[:2]:
        body = copy.deepcopy(entry["sealed_sum"])
        body["commitments"] = fake_commitments
        body = {k: v for k, v in body.items() if k not in {"signature", "encrypted_share"}}
        sender = entry["sender"]
        forged.append(dict(sender=sender, sealed_sum=seal(manifest,
            identity_for(nodes[sender + 1], manifest), body, fake_shares[body["index"]])))
    # Two corrupt identities exceed f=1: fail closed, regardless of order.
    for replies in (forged + entries[2:], entries[2:] + forged):
        with pytest.raises(ProtocolError, match="commitments disagree"):
            recover_key(manifest, aggregator, replies, [0, 4], 1)


@pytest.mark.parametrize("case", [7], indirect=True)
def test_f_faulty_commitment_replies_cannot_select_a_false_aggregate(case):
    from trustlessfl.crypto import pedersen_split
    manifest, nodes, _, _ = case
    entries, aggregator, expected = aggregate_entries(case)
    fake_shares, fake_commitments = pedersen_split(111, threshold(manifest), 7)
    forged = []
    for entry in entries[:2]:  # f=2, t=3: this commitment group cannot qualify.
        body = {k: v for k, v in entry["sealed_sum"].items()
                if k not in {"signature", "encrypted_share"}}
        body["commitments"] = fake_commitments
        sender = entry["sender"]
        forged.append(dict(sender=sender, sealed_sum=seal(manifest,
            identity_for(nodes[sender + 1], manifest), body, fake_shares[body["index"]])))
    for replies in (forged + entries[2:], entries[2:] + forged):
        assert recover_key(manifest, aggregator, replies, [0, 4], 1) == expected


@pytest.mark.parametrize("case", [7], indirect=True)
def test_legacy_encrypted_transcript_still_uses_original_two_share_threshold(case):
    from trustlessfl.aion_source_sharing import share_seed, receive_seed, sum_keys
    manifest, nodes, _, _ = case
    manifest["sharing_profile"].pop("threshold_rule")
    manifest["sharing_profile"].pop("threshold")
    saved = {actor: {} for actor in manifest["committee"]}
    for sender, secret in ((0, 4), (4, 16)):
        for event in share_seed(manifest, identity_for(nodes[sender + 1], manifest), secret):
            recipient = event["recipient"]
            receive_seed(manifest, identity_for(nodes[recipient + 1], manifest), saved[recipient], event["body"])
    entries = [dict(sender=actor, **sum_keys(manifest, identity_for(nodes[actor + 1], manifest),
                   saved[actor]["shares"], [0, 4], 1)) for actor in manifest["committee"][:2]]
    aggregator = identity_for(nodes[manifest["aggregator"] + 1], manifest)
    assert recover_key(manifest, aggregator, entries, [0, 4], 1) == 20
    damaged = copy.deepcopy(entries[0])
    damaged["sealed_sum"]["signature"] = "00" * 64
    with pytest.raises(ProtocolError, match="signature"):
        recover_key(manifest, aggregator, [damaged, *entries], [0, 4], 1)


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

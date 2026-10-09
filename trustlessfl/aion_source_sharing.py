"""One-time randomized key sharing for the source learning adapter.

Original HPRF outputs are unchanged. Pedersen shares use ORDER, rather than
the author's group modulus as a scalar field. Flower relays signed ciphertext;
only the addressed actor decrypts. This does not resolve scaled-MGF carry or
key-domain attacks. The separate selection module gates paper-MGF key queries;
sharing alone does not authorize a cohort or prevent across-round leakage.
"""

import json
from pathlib import Path

from .crypto import (Identity, ORDER, ProtocolError, aggregate_commitments,
                     decrypt_pedersen_share, encrypt_pedersen_share,
                     pedersen_reconstruct_pair, pedersen_split, pedersen_verify_share,
                     sum_pedersen_shares, verify)

MODE = "recipient-encrypted-pedersen-v1"
THRESHOLD_RULE = "bft-f-plus-one-min-two-v1"


def enabled(manifest):
    return manifest.get("sharing_profile", {}).get("kind") == MODE


def threshold(manifest):
    """Pin fresh ASR to f+1; preserve historical sharing transcripts.

    The Pedersen adapter has a two-share minimum even for n=2/3 (f=0).
    This numerical floor is not a claim of Byzantine tolerance for n<4.
    """
    size = len(manifest["committee"])
    profile = manifest.get("sharing_profile", {})
    if "threshold_rule" not in profile and "threshold" not in profile:
        return max(2, size // 3)
    expected = max(2, (size - 1) // 3 + 1)
    if (profile.get("kind") != MODE
            or profile.get("threshold_rule") != THRESHOLD_RULE
            or type(profile.get("threshold")) is not int
            or profile["threshold"] != expected):
        raise ProtocolError("invalid source ASR threshold profile")
    return expected


def identity_for(config, manifest):
    threshold(manifest)  # Reject mismatched policy before actor state changes.
    actor = str(config["aion-source-id"])
    try:
        identity = Identity.from_private(json.loads(Path(config["aion-source-identity"]).read_text()))
        registry = manifest["source_transport_registry"]
        if identity.name != actor or identity.public() != registry[actor]:
            raise ProtocolError("source transport identity differs from pinned recipient")
        if manifest["prime"] != ORDER:
            raise ProtocolError("source randomized sharing requires subgroup scalar field")
        return identity
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ProtocolError("invalid source transport identity or recipient") from exc


def seal(manifest, identity, body, pair):
    body = dict(body)
    recipient = str(body["recipient"])
    body["encrypted_share"] = encrypt_pedersen_share(pair,
        manifest["source_transport_registry"][recipient]["encryption"],
        task=manifest["task"] + "/" + body["msg"], sender=identity.name,
        recipient=recipient, round_id=body["round"], coordinate=body["index"],
        commitments=body["commitments"])
    # Context beyond the cipher's AAD (members, task, packet type) is signed.
    body["signature"] = identity.sign(body)["signature"]
    return body


def open_share(manifest, identity, body, *, kind, round_id):
    expected = {"msg", "sender", "recipient", "round", "index", "commitments",
                "encrypted_share", "signature"}
    if kind == "AGGREGATE_KEY_SHARE":
        expected.add("members")
    if not isinstance(body, dict) or set(body) != expected:
        raise ProtocolError("invalid encrypted source share schema")
    sender = body["sender"]
    if (type(sender) is not int or sender not in manifest["clients"]
            or body["msg"] != kind or type(body["round"]) is not int
            or body["round"] != round_id or type(body["recipient"]) is not int
            or body["recipient"] != int(identity.name)
            or type(body["index"]) is not int):
        raise ProtocolError("encrypted source share recipient or context mismatch")
    unsigned = {k: v for k, v in body.items() if k != "signature"}
    verify(dict(sender=str(sender), body=unsigned, signature=body["signature"]),
           manifest["source_transport_registry"], sender=str(sender))
    pair = decrypt_pedersen_share(body["encrypted_share"], identity,
        task=manifest["task"] + "/" + kind, sender=str(sender), round_id=round_id,
        coordinate=body["index"], commitments=body["commitments"])
    if not pedersen_verify_share(body["index"], pair, body["commitments"]):
        raise ProtocolError("invalid randomized source VSS share")
    return pair


def share_seed(manifest, identity, secret):
    committee = manifest["committee"]
    pairs, commitments = pedersen_split(secret, threshold(manifest), len(committee))
    return [dict(recipient=recipient, body=seal(manifest, identity,
        dict(msg="SHARED_MASK", sender=int(identity.name), recipient=recipient,
             round=1, index=index, commitments=commitments), pairs[index]))
        for index, recipient in enumerate(committee, 1)]


def receive_seed(manifest, identity, state, body):
    expected_index = manifest["committee"].index(int(identity.name)) + 1
    if body.get("index") != expected_index:
        raise ProtocolError("wrong encrypted source share recipient index")
    pair = open_share(manifest, identity, body, kind="SHARED_MASK", round_id=1)
    if len(body["commitments"]) != threshold(manifest):
        raise ProtocolError("source share commitment threshold mismatch")
    stored = state.setdefault("shares", {})
    decoded = dict(shared_mask=[expected_index, *pair], commitments=body["commitments"],
                   sender=body["sender"], msg="SHARED_MASK")
    name = str(body["sender"])
    if name in stored and stored[name] != decoded:
        raise ProtocolError("conflicting one-time randomized source share")
    stored[name] = decoded


def sum_keys(manifest, identity, stored, members, round_id):
    pair = sum_pedersen_shares([stored[str(name)]["shared_mask"][1:] for name in members])
    commitments = aggregate_commitments([stored[str(name)]["commitments"] for name in members])
    index = manifest["committee"].index(int(identity.name)) + 1
    body = seal(manifest, identity, dict(msg="AGGREGATE_KEY_SHARE",
        sender=int(identity.name), recipient=manifest["aggregator"], round=round_id,
        index=index, members=members, commitments=commitments), pair)
    return dict(sealed_sum=body)


def _verified_aggregate_share(manifest, identity, entry, members, round_id, required):
    if not isinstance(entry, dict) or set(entry) != {"sender", "sealed_sum"}:
        raise ProtocolError("invalid source aggregate share entry")
    body, sender = entry["sealed_sum"], entry["sender"]
    if (type(sender) is not int or sender not in manifest["committee"]
            or not isinstance(body, dict) or body.get("sender") != sender
            or body.get("members") != members
            or body.get("index") != manifest["committee"].index(sender) + 1
            or not isinstance(body.get("commitments"), list)
            or len(body["commitments"]) != required):
        raise ProtocolError("source aggregate share members or sender mismatch")
    pair = open_share(manifest, identity, body, kind="AGGREGATE_KEY_SHARE", round_id=round_id)
    return body["index"], pair, body["commitments"]


def recover_key_opening(manifest, identity, entries, members, round_id):
    required = threshold(manifest)
    if not isinstance(entries, list):
        raise ProtocolError("invalid source aggregate share collection")
    modern = manifest.get("sharing_profile", {}).get("threshold_rule") == THRESHOLD_RULE
    groups = {}
    for entry in entries:
        try:
            index, pair, commitments = _verified_aggregate_share(
                manifest, identity, entry, members, round_id, required)
        except (ProtocolError, KeyError, TypeError, ValueError):
            if not modern:
                raise
            # Algorithm 3 collects valid authenticated shares. Reject an
            # invalid packet, not the entire valid reconstruction set.
            continue
        group = tuple(commitments)
        if not modern and groups and group not in groups:
            raise ProtocolError("source aggregate commitments disagree")
        groups.setdefault(group, {})[index] = pair
    candidates = [(list(commitments), pairs) for commitments, pairs in groups.items()
                  if len(pairs) >= required]
    if not candidates:
        raise ProtocolError("source randomized shares below threshold")
    if len(candidates) != 1:
        # Never pick an arbitrary commitment set if the fault assumption is
        # violated. A group cannot qualify with f faulty identities alone.
        raise ProtocolError("source aggregate commitments disagree")
    commitments, pairs = candidates[0]
    key, blind = pedersen_reconstruct_pair(pairs, commitments)
    from .source_profiles import key_sum_valid
    if not key_sum_valid(manifest, key, len(members)):
        raise ProtocolError("source aggregate key outside author key domain")
    return dict(key=key, blind=blind)


def recover_key(manifest, identity, entries, members, round_id):
    return recover_key_opening(manifest, identity, entries, members, round_id)["key"]

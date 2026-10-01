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
                     pedersen_reconstruct, pedersen_split, pedersen_verify_share,
                     sum_pedersen_shares, verify)

MODE = "recipient-encrypted-pedersen-v1"


def enabled(manifest):
    return manifest.get("sharing_profile", {}).get("kind") == MODE


def identity_for(config, manifest):
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
    threshold = max(2, len(committee) // 3)
    pairs, commitments = pedersen_split(secret, threshold, len(committee))
    return [dict(recipient=recipient, body=seal(manifest, identity,
        dict(msg="SHARED_MASK", sender=int(identity.name), recipient=recipient,
             round=1, index=index, commitments=commitments), pairs[index]))
        for index, recipient in enumerate(committee, 1)]


def receive_seed(manifest, identity, state, body):
    expected_index = manifest["committee"].index(int(identity.name)) + 1
    if body.get("index") != expected_index:
        raise ProtocolError("wrong encrypted source share recipient index")
    pair = open_share(manifest, identity, body, kind="SHARED_MASK", round_id=1)
    if len(body["commitments"]) != max(2, len(manifest["committee"]) // 3):
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


def recover_key(manifest, identity, entries, members, round_id):
    pairs, commitments = {}, None
    for entry in entries:
        body = entry["sealed_sum"]
        sender = entry["sender"]
        if (body["sender"] != sender or sender not in manifest["committee"]
                or body["members"] != members
                or body["index"] != manifest["committee"].index(sender) + 1):
            raise ProtocolError("source aggregate share members or sender mismatch")
        pair = open_share(manifest, identity, body, kind="AGGREGATE_KEY_SHARE", round_id=round_id)
        if commitments is not None and commitments != body["commitments"]:
            raise ProtocolError("source aggregate commitments disagree")
        commitments = body["commitments"]
        pairs[body["index"]] = pair
    threshold = max(2, len(manifest["committee"]) // 3)
    if commitments is None or len(commitments) != threshold or len(pairs) < threshold:
        raise ProtocolError("source randomized shares below threshold")
    key = pedersen_reconstruct(pairs, commitments)
    if not len(members) <= key <= len(members) * 100000:
        raise ProtocolError("source aggregate key outside author key domain")
    return key

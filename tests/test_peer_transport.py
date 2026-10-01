"""Peer messages are independent of Flower's coordinator transport."""

import asyncio
import copy
import secrets
import json
import select
import subprocess
import sys
from pathlib import Path

import pytest
from flwr.app import Context, Message, RecordDict

from trustlessfl.client_app import (app as client_app, payload, peer_update_path,
                                   process_local_request, records)
from trustlessfl.crypto import Identity, ProtocolError, digest, verify
from trustlessfl.demo import provision
from trustlessfl.hotstuff import (candidate_claim, claim as hotstuff_claim,
                                  make_timeout_qc, slot_for, timeout_claim)
from trustlessfl.local_grid import ProcessGrid
from trustlessfl.peer_party import PeerParty
from trustlessfl.peer_transport import PeerTransport, _frame, _read, open_peer, seal_peer
from trustlessfl.protocol import Parameters, Party, certificate
from trustlessfl.workflow import AionWorkflow


def test_signed_peer_delivery_and_replay_rejection():
    async def scenario():
        p = Parameters("peer-test", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
        identities = {name: Identity.generate(name) for name in p.aggregators}
        registry = {name: identity.public() for name, identity in identities.items()}
        received = []

        async def handle(sender, kind, transcript):
            received.append((sender, kind, transcript))

        def transport(name, handler):
            peers = {peer: ("127.0.0.1", 1) for peer in p.aggregators if peer != name}
            return PeerTransport(identities[name], p, registry, peers, handler)

        first = transport("a0", handle)
        second = transport("a1", handle)
        try:
            first_address = await first.start("127.0.0.1", 0)
            second_address = await second.start("127.0.0.1", 0)
            first.addresses["a1"] = second_address
            second.addresses["a0"] = first_address
            ack = await first.send("a1", "vote", {"round": 1, "claim": "example"})
            assert verify(ack, registry, sender="a1")["status"] == "accepted"
            assert received == [("a0", "vote", {"round": 1, "claim": "example"})]

            body = {"protocol": "aion-peer-v1", "task": p.task, "recipient": "a1",
                    "kind": "timeout", "nonce": secrets.token_hex(16),
                    "transcript": {"round": 1, "view": 0}}
            request = identities["a0"].sign(body)

            async def raw_send(packet, *, tamper=False):
                reader, writer = await asyncio.open_connection(*second_address)
                try:
                    sealed = seal_peer(packet, "a1", registry, p.task)
                    if tamper:
                        sealed["ciphertext"] = ("00" if sealed["ciphertext"][:2] != "00" else "01") + sealed["ciphertext"][2:]
                    frame = _frame(sealed)
                    assert b'"claim"' not in frame
                    writer.write(frame)
                    await writer.drain()
                    return open_peer(await _read(reader), identities["a0"], registry, p.task)
                finally:
                    writer.close()
                    await writer.wait_closed()

            response = await raw_send(request)
            assert verify(response, registry, sender="a1")["request"] == digest(request)
            with pytest.raises(asyncio.IncompleteReadError):
                await raw_send(request)
            assert len(received) == 2

            forged = {**request, "signature": "00" * 64}
            with pytest.raises(asyncio.IncompleteReadError):
                await raw_send(forged)
            with pytest.raises(asyncio.IncompleteReadError):
                await raw_send(identities["a0"].sign({**body, "nonce": secrets.token_hex(16)}), tamper=True)
            foreign = identities["a0"].sign({**body, "task": "foreign", "nonce": secrets.token_hex(16)})
            with pytest.raises(asyncio.IncompleteReadError):
                await raw_send(foreign)
            with pytest.raises(ProtocolError, match="decryption failed"):
                open_peer(seal_peer(request, "a1", registry, p.task), identities["a0"], registry, p.task)
            assert len(received) == 2
        finally:
            await first.close()
            await second.close()

    asyncio.run(scenario())


def test_peer_transport_rejects_unpinned_or_incomplete_roster():
    p = Parameters("peer-config-test", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    identities = {name: Identity.generate(name) for name in p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}

    async def handle(sender, kind, transcript):
        pass

    with pytest.raises(ProtocolError, match="not pinned"):
        PeerTransport(Identity.generate("a0"), p, registry, {}, handle)
    with pytest.raises(ProtocolError, match="wrong aggregator roster"):
        PeerTransport(identities["a0"], p, registry, {"a1": ("127.0.0.1", 9000)}, handle)


def test_client_delivers_signed_update_to_encrypted_aggregator_inbox(tmp_path):
    p = Parameters("peer-client-update", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    client_identity = Identity.from_private(json.loads(
        Path(configs["c0"]["aion-identity"]).read_text()))
    update = client_identity.sign(p.claim("update", 1, parent="a" * 64, vector=[1, 2, 3]))
    peer = PeerParty(configs["a0"], {name: ("127.0.0.1", 1)
                                    for name in p.aggregators if name != "a0"})

    async def unused_handler(sender, kind, transcript):
        raise AssertionError("client sender cannot accept inbound peer messages")

    client = PeerTransport(client_identity, p, manifest["registry"],
                           {name: ("127.0.0.1", 1) for name in p.aggregators},
                           unused_handler)

    async def scenario():
        address = await peer.start("127.0.0.1", 0)
        client.addresses["a0"] = address
        try:
            with pytest.raises(ProtocolError, match="outbound only"):
                await client.start("127.0.0.1", 0)
            with pytest.raises(ProtocolError, match="invalid peer message"):
                await client.send("a0", "qc", {"action": "commit"})
            receipt = await client.request("a0", "client-update",
                                           {"action": "deliver_update", "update": update})
            assert verify(receipt, manifest["registry"], sender="a0") == p.claim(
                "update-received", 1, client="c0", update=digest(update))
            await client.request("a0", "client-update",
                                 {"action": "deliver_update", "update": update})
            forged = {**update, "signature": "00" * 64}
            with pytest.raises(ProtocolError, match="peer delivery failed"):
                await client.send("a0", "client-update",
                                  {"action": "deliver_update", "update": forged})
            conflicting = client_identity.sign(p.claim("update", 1, parent="a" * 64,
                                                        vector=[4, 5, 6]))
            with pytest.raises(ProtocolError, match="peer delivery failed"):
                await client.send("a0", "client-update",
                                  {"action": "deliver_update", "update": conflicting})
        finally:
            await peer.close()

    asyncio.run(scenario())
    path = peer_update_path(Path(configs["a0"]["aion-identity"]), p.task, "a0", 1)
    assert json.loads(path.read_text())["updates"] == {"c0": update}


def test_flower_clientapp_keeps_training_and_dual_delivers_update(tmp_path):
    p = Parameters("flower-dual-delivery", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    enrollments = [process_local_request(configs[name], {"action": "enroll"})
                   for name in p.clients]
    genesis_votes = [process_local_request(configs[name], {"action": "initialize",
                                                           "enrollments": enrollments})
                     for name in p.aggregators]
    model = certificate(genesis_votes[0]["body"], genesis_votes, p, manifest["registry"])
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name})
             for name in p.aggregators[:3]}
    stalled = PeerParty(configs["a3"], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != "a3"})
    stall_release = asyncio.Event()
    original_handler = stalled.transport.handler

    async def slow_update(sender, kind, transcript):
        if kind == "client-update":
            await stall_release.wait()
        return await original_handler(sender, kind, transcript)

    stalled.transport.handler = slow_update
    addresses_path = tmp_path / "client-peers.json"
    client_config = {**configs["c0"], "aion-peer-addresses": str(addresses_path)}

    def train_reply():
        request = Message(records({"action": "train", "model": model}), dst_node_id=1,
                          message_type="query.aion")
        context = Context(1, 1, client_config, RecordDict(), {})
        return client_app(request, context)

    async def scenario():
        started = []
        try:
            addresses = {name: ["127.0.0.1", 1] for name in p.aggregators}
            for name in ("a0", "a1"):
                addresses[name] = list(await peers[name].start("127.0.0.1", 0))
                started.append(name)
            addresses_path.write_text(json.dumps(addresses))
            assert (await asyncio.to_thread(train_reply)).has_error()
            addresses["a2"] = list(await peers["a2"].start("127.0.0.1", 0))
            started.append("a2")
            addresses_path.write_text(json.dumps(addresses))
            reply = await asyncio.to_thread(train_reply)
            assert not reply.has_error()
            update = payload(reply)
            assert verify(update, manifest["registry"], sender="c0")["kind"] == "update"
            addresses["a3"] = list(await stalled.start("127.0.0.1", 0))
            addresses_path.write_text(json.dumps(addresses))
            started_at = asyncio.get_running_loop().time()
            retry = await asyncio.to_thread(train_reply)
            assert not retry.has_error() and payload(retry) == update
            assert asyncio.get_running_loop().time() - started_at < 5
            return update
        finally:
            stall_release.set()
            await stalled.close()
            for name in started:
                await peers[name].close()

    update = asyncio.run(scenario())
    for name in p.aggregators[:3]:
        path = peer_update_path(Path(configs[name]["aion-identity"]), p.task, name, 1)
        assert json.loads(path.read_text())["updates"]["c0"] == update


def test_peers_continue_after_flower_stops_before_roster_preparation(tmp_path):
    p = Parameters("peer-before-roster", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name},
                             auto_complete=name == "a0", recovery_delay=0.0)
             for name in p.aggregators[:3]}
    addresses_path = tmp_path / "client-peers.json"
    proof_path = Path(configs["a0"]["aion-identity"]).parent / (
        f"peer-decisions-{digest({'task': p.task, 'party': 'a0'})}.json")

    class CrashBeforeRoster(AionWorkflow):
        def quorum_call(self, grid, action, **kwargs):
            if action == "prepare":
                raise RuntimeError("Flower stopped before roster preparation")
            return super().quorum_call(grid, action, **kwargs)

    async def scenario():
        try:
            addresses = {name: ["127.0.0.1", 1] for name in p.aggregators}
            for name, peer in peers.items():
                addresses[name] = list(await peer.start("127.0.0.1", 0))
            for peer in peers.values():
                for name in peer.transport.addresses:
                    peer.transport.addresses[name] = tuple(addresses[name])
            addresses_path.write_text(json.dumps(addresses))
            for name in p.clients:
                configs[name]["aion-peer-addresses"] = str(addresses_path)

            def crash_flower():
                with ProcessGrid(nodes) as grid:
                    with pytest.raises(RuntimeError, match="before roster preparation"):
                        CrashBeforeRoster(p, manifest["registry"], timeout=45.0).run(grid, 1)

            await asyncio.to_thread(crash_flower)
            for _ in range(300):
                if proof_path.exists():
                    break
                await asyncio.sleep(0.1)
            else:
                raise AssertionError("peer sidecar did not prepare delivered updates")
        finally:
            for peer in peers.values():
                await peer.close()

    asyncio.run(scenario())
    proof = json.loads(proof_path.read_text())["certificates"]["1"]
    assert len(proof["model"]["votes"]) == p.quorum
    assert len(proof["decision"]["votes"]) == p.quorum
    for name in p.aggregators[:3]:
        path = peer_update_path(Path(configs[name]["aion-identity"]), p.task, name, 1)
        assert set(json.loads(path.read_text())["updates"]) == set(p.clients)
    # Flower may restart without the optional dual-delivery transport.
    for name in p.clients:
        configs[name].pop("aion-peer-addresses")
    with ProcessGrid(nodes) as grid:
        history = AionWorkflow(p, manifest["registry"], timeout=45.0).run(grid, 2)
    assert [model["body"]["round"] for model in history] == [0, 1, 2]
    assert history[1]["body"] == proof["model"]["body"]


def test_peer_update_reconciliation_survives_split_delivery_and_restart(tmp_path):
    p = Parameters("split-update-quorums", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    enrollments = [process_local_request(configs[name], {"action": "enroll"}) for name in p.clients]
    votes = [process_local_request(configs[name], {"action": "initialize", "enrollments": enrollments})
             for name in p.aggregators]
    genesis = certificate(votes[0]["body"], votes, p, manifest["registry"])

    def train(name, model, config):
        request = Message(records({"action": "train", "model": model}), dst_node_id=1,
                          message_type="query.aion")
        reply = client_app(request, Context(1, 1, config, RecordDict(), {}))
        assert not reply.has_error()
        return payload(reply)

    async def unused_handler(*_args):
        raise AssertionError("outbound client transport")

    def make_peers(names, auto=False):
        return {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                               for other in p.aggregators if other != name},
                                auto_complete=auto and name == "a0", recovery_delay=0.0)
                for name in names}

    async def start_peers(peers):
        addresses = {name: ("127.0.0.1", 1) for name in p.aggregators}
        for name, peer in peers.items():
            addresses[name] = await peer.start("127.0.0.1", 0)
        for peer in peers.values():
            for name in peer.transport.addresses:
                peer.transport.addresses[name] = addresses[name]
        return addresses

    async def wait_decision(peers, round_id):
        path, _ = peers["a0"]._proof_paths()
        async with asyncio.timeout(60):
            while True:
                if path.exists():
                    proof = json.loads(path.read_text())["certificates"].get(str(round_id))
                    if proof is not None:
                        assert len(proof["decision"]["votes"]) == p.quorum
                        return proof["model"]
                await asyncio.sleep(0.05)

    async def scenario():
        peers = make_peers(p.aggregators)
        try:
            addresses = await start_peers(peers)
            # Each client succeeds with 3 receipts, but only 2 aggregators
            # initially have both updates. One of those holders then fails.
            for name, omitted in (("c0", "a0"), ("c1", "a1")):
                path = tmp_path / f"{name}-peers.json"
                path.write_text(json.dumps({**addresses, omitted: ("127.0.0.1", 1)}))
                await asyncio.to_thread(train, name, genesis,
                                        {**configs[name], "aion-peer-addresses": str(path)})
            parent = digest(genesis["body"])
            assert [u["sender"] for u in peers["a0"]._read_inbox(1, parent)] == ["c1"]
            assert [u["sender"] for u in peers["a1"]._read_inbox(1, parent)] == ["c0"]
        finally:
            for peer in peers.values():
                await peer.close()

        # Restart from durable partial inboxes; a3 stays unavailable. Only a0
        # has an automatic worker, so the other peers must learn via relays.
        peers = make_peers(p.aggregators[:3], auto=True)
        try:
            addresses = await start_peers(peers)
            model = await wait_decision(peers, 1)
            for peer in peers.values():
                assert len(peer._inbox_updates(genesis["body"])) == len(p.clients)

            # A completed round's durable proposal must not prevent fetching
            # the next round. Training still runs through Flower ClientApp.
            for name, holder in (("c0", "a1"), ("c1", "a2")):
                update = await asyncio.to_thread(train, name, model, configs[name])
                identity = Identity.from_private(json.loads(Path(configs[name]["aion-identity"]).read_text()))
                client = PeerTransport(identity, p, manifest["registry"], addresses, unused_handler)
                await client.request(holder, "client-update", {"action": "deliver_update", "update": update})
            second = await wait_decision(peers, 2)
            assert second["body"]["parent"] == digest(model["body"])
        finally:
            for peer in peers.values():
                await peer.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("stall_leader,mgf,broken_client", [
    (False, False, False), (True, False, False),
    (False, True, False), (False, True, True), (False, "projection", False),
    (False, "percentile", False), (False, "artifact-bound", False)])
def test_hotstuff_peer_continues_after_flower_and_initial_leader_stop(
        tmp_path, stall_leader, mgf, broken_client):
    p = Parameters("peer-hotstuff-leader-stop", ("c0", "c1", "c2") if broken_client else ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), hotstuff=True,
                   **({"mgf_beta": "0.2", "mgf_initial_alpha": "0.2",
                       "mgf_initial_bound": "5", "mgf_initial_term": "1",
                       "mgf_projection": (1, 3) if mgf in ("projection", "percentile", "artifact-bound") else (),
                       "mgf_percentile": mgf in ("percentile", "artifact-bound"),
                       "mgf_artifact_bound": mgf == "artifact-bound"} if mgf else {}))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name},
                             auto_complete=True, recovery_delay=0.0)
             for name in p.aggregators[1:]}
    if broken_client:
        attacker = Identity.from_private(json.loads(Path(configs["c2"]["aion-identity"]).read_text()))
        for peer in peers.values():
            original_store = peer._store_client_update

            def store_with_broken_share(sender, transcript, *, store=original_store):
                if sender == "c2":
                    body = copy.deepcopy(transcript["update"]["body"])
                    for recipient in p.aggregators[:2]:
                        body["mgf"]["mask_packets"][recipient] = []
                    transcript = {**transcript, "update": attacker.sign(body)}
                return store(sender, transcript)

            peer._store_client_update = store_with_broken_share
    stall_release = asyncio.Event()
    if stall_leader:
        peers["a0"] = PeerParty(configs["a0"], {name: ("127.0.0.1", 1)
                                                   for name in p.aggregators[1:]})
        original_handler = peers["a0"].transport.handler

        async def delayed_hotstuff(sender, kind, transcript):
            if kind == "hotstuff":
                await stall_release.wait()
            return await original_handler(sender, kind, transcript)

        peers["a0"].transport.handler = delayed_hotstuff
    addresses_path = tmp_path / "client-peers.json"
    proof_path, _ = peers["a1"]._proof_paths()

    class CrashBeforeRoster(AionWorkflow):
        def quorum_call(self, grid, action, **kwargs):
            if action == "prepare":
                raise RuntimeError("Flower stopped before HotStuff roster")
            return super().quorum_call(grid, action, **kwargs)

    async def scenario():
        try:
            addresses = {name: ["127.0.0.1", 1] for name in p.aggregators}
            for name, peer in peers.items():
                addresses[name] = list(await peer.start("127.0.0.1", 0))
            for peer in peers.values():
                for name in peer.transport.addresses:
                    peer.transport.addresses[name] = tuple(addresses[name])
            addresses_path.write_text(json.dumps(addresses))
            for name in p.clients:
                configs[name]["aion-peer-addresses"] = str(addresses_path)

            def crash_flower():
                with ProcessGrid(nodes) as grid:
                    with pytest.raises(RuntimeError, match="before HotStuff roster"):
                        CrashBeforeRoster(p, manifest["registry"], timeout=45.0).run(grid, 1)

            await asyncio.to_thread(crash_flower)
            started = asyncio.get_running_loop().time()
            try:
                async with asyncio.timeout(100):
                    while not proof_path.exists():
                        await asyncio.sleep(0.1)
            except TimeoutError as exc:
                diagnostics = {
                    name: {"stage": peer._recovery_stage,
                           "timeout": peer._peer_timeout,
                           "failures": peer._recovery_failures[-5:],
                           "stack": [(frame.f_code.co_name, frame.f_lineno)
                                     for frame in peer._worker.get_stack(limit=4)]
                           if peer._worker is not None else []}
                    for name, peer in peers.items() if peer.auto_complete}
                raise AssertionError(f"peer recovery stalled: {diagnostics}") from exc
            if stall_leader:
                assert asyncio.get_running_loop().time() - started < 30
            proof = json.loads(proof_path.read_text())["certificates"]["1"]
            assert proof["model"]["hotstuff"]["body"]["view"] >= 2
            assert proof["model"]["hotstuff"]["body"]["stage"] == "commit"
            assert len(proof["decision"]["votes"]) == p.quorum
            if mgf in ("percentile", "artifact-bound"):
                roster_body = proof["model"]["roster_certificate"]["body"]
                assert roster_body["members"] == ["c0", "c1"]
                assert roster_body["mgf_selection"]["selected_count"] == 2
                assert roster_body["mgf_selection"]["small_cohort_floor_override"]
                assert roster_body["mgf_selection"]["cohort"] == ["c0", "c1"]
            if broken_client:
                stored = peers["a1"]._read_inbox(1, proof["model"]["body"]["parent"])
                corrupted = next(update for update in stored if update["sender"] == "c2")
                assert corrupted["body"]["mgf"]["mask_packets"]["a1"] == []
                assert proof["model"]["roster_certificate"]["body"]["members"] == ["c0", "c1"]
            return proof["model"]
        finally:
            stall_release.set()
            for peer in peers.values():
                await peer.close()

    model = asyncio.run(scenario())
    assert model["body"]["round"] == 1


def test_mgf_peer_fetches_missing_honest_update_after_admission_failure(tmp_path):
    p = Parameters("peer-mgf-admission-reconcile", ("c0", "c1", "c2"),
                   ("a0", "a1", "a2", "a3"), dimension=2, hotstuff=True,
                   mgf_beta="0.2", mgf_initial_alpha="0.2",
                   mgf_initial_bound="5", mgf_initial_term="1")
    manifest_path, nodes = provision(tmp_path / "identities", p)
    registry = json.loads(manifest_path.read_text())["registry"]
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    enrollments = [process_local_request(configs[name], {"action": "enroll"})
                   for name in p.clients]
    genesis_votes = [process_local_request(configs[name], {
        "action": "initialize", "enrollments": enrollments}) for name in p.aggregators]
    model = certificate(genesis_votes[0]["body"], genesis_votes, p, registry)
    updates = {name: process_local_request(configs[name], {
        "action": "train", "model": model}) for name in p.clients}
    attacker = Identity.from_private(json.loads(Path(configs["c2"]["aion-identity"]).read_text()))
    bad_body = copy.deepcopy(updates["c2"]["body"])
    for recipient in ("a1", "a2"):
        bad_body["mgf"]["mask_packets"][recipient] = []
    broken = attacker.sign(bad_body)
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name})
             for name in p.aggregators[1:]}
    for name, update in (("a1", updates["c0"]), ("a1", broken),
                         ("a2", updates["c1"]), ("a2", broken)):
        peers[name]._store_client_update(update["sender"], {
            "action": "deliver_update", "update": update})
    assert [u["sender"] for u in peers["a1"]._inbox_updates(model["body"])] == ["c0", "c2"]

    async def scenario():
        try:
            addresses = {name: await peer.start("127.0.0.1", 0)
                         for name, peer in peers.items()}
            for peer in peers.values():
                for name in addresses:
                    if name != peer.transport.identity.name:
                        peer.transport.addresses[name] = addresses[name]
            result = await peers["a1"].prepare_from_inbox(timeout=2.0)
            assert result["roster_certificate"]["body"]["members"] == ["c0", "c1"]
            assert [u["sender"] for u in peers["a1"]._read_inbox(1, digest(model["body"]))] == [
                "c0", "c1", "c2"]
            return result
        finally:
            for peer in peers.values():
                await peer.close()

    assert asyncio.run(scenario())["body"]["round"] == 1


def test_hotstuff_status_reads_slower_higher_view_after_fast_old_quorum(tmp_path, monkeypatch):
    """A silent faulty replica cannot make a fast stale quorum hide a view QC."""
    import trustlessfl.hotstuff as hotstuff_module
    import trustlessfl.peer_party as peer_party_module

    p = Parameters("peer-hotstuff-status", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), hotstuff=True)
    _, nodes = provision(tmp_path / "identities", p)
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    identities = {name: Identity.from_private(json.loads(Path(configs[name]["aion-identity"]).read_text()))
                  for name in p.aggregators}
    peer = PeerParty(configs["a1"], {name: ("127.0.0.1", 1)
                                      for name in p.aggregators if name != "a1"})
    value = p.claim("roster", 1, parent="a" * 64, members=list(p.clients),
                    updates="b" * 64, late="")
    slot = slot_for(value)
    timeout_body = timeout_claim(p, slot, 1)
    timeout_qc = make_timeout_qc(p, peer.transport.registry, slot, 1,
                                 [identities[name].sign(timeout_body)
                                  for name in ("a0", "a1", "a3")])

    def status(name, view):
        return identities[name].sign(hotstuff_claim(
            p, slot, "status", view, decision=None, entry=None,
            timeout_qc=timeout_qc if view == 2 else None))

    def local(_config, request):
        if request["action"] == "hotstuff_candidate":
            return identities["a1"].sign(candidate_claim(p, value))
        assert request["op"] == "status"
        return status("a1", 1)

    async def remote(name, kind, request, *, timeout):
        assert kind == "hotstuff" and request["op"] == "status"
        if name == "a3":
            await asyncio.sleep(0.05)
        return status(name, 2 if name == "a3" else 1)

    async def inspect_status(_p, _registry, _value, _command, call):
        request = {"action": "hotstuff", "slot": slot, "op": "status"}
        fast = await call(p.aggregators, request)
        drained = await call(p.aggregators, {**request, "drain": True})
        return ({reply["sender"]: reply["body"]["view"] for reply in fast},
                {reply["sender"]: reply["body"]["view"] for reply in drained})

    monkeypatch.setattr(peer_party_module, "process_local_request", local)
    monkeypatch.setattr(peer.transport, "request", remote)
    monkeypatch.setattr(hotstuff_module, "run_round", inspect_status)
    fast, drained = asyncio.run(peer._peer_hotstuff_certificate({"action": "prepare"}, timeout=1))
    assert fast == {"a0": 1, "a1": 1, "a2": 1}
    assert drained == {"a0": 1, "a1": 1, "a2": 1, "a3": 2}


@pytest.mark.parametrize("fails", [False, True])
def test_peer_service_reports_recovery_worker_exit(monkeypatch, tmp_path, fails):
    """A dead recovery loop must not leave a healthy-looking sidecar."""
    from types import SimpleNamespace
    import trustlessfl.peer_service as peer_service

    instances = []

    class FakePeer:
        def __init__(self, _config, _addresses, **_kwargs):
            self.transport = SimpleNamespace(identity=SimpleNamespace(name="a1"))
            self._worker = None
            self.closed = False
            instances.append(self)

        async def start(self, _host, _port):
            async def worker():
                if fails:
                    raise RuntimeError("injected recovery failure")

            self._worker = asyncio.create_task(worker())
            return "127.0.0.1", 12345

        async def close(self):
            self.closed = True
            await asyncio.gather(self._worker, return_exceptions=True)

    monkeypatch.setattr(peer_service, "_addresses", lambda _path: {})
    monkeypatch.setattr(peer_service, "PeerParty", FakePeer)
    args = SimpleNamespace(peers=tmp_path / "unused", host="127.0.0.1", port=0,
                           manifest=tmp_path / "unused", identity=tmp_path / "unused",
                           recovery_delay=0, allow_insecure_network=False)
    with pytest.raises(RuntimeError, match=("injected recovery failure" if fails else
                                            "stopped unexpectedly")):
        asyncio.run(peer_service.serve(args))
    assert instances[0].closed


def test_peer_close_releases_listener_after_worker_failure():
    closed = []

    async def scenario():
        peer = object.__new__(PeerParty)

        async def worker():
            raise RuntimeError("recovery failed")

        async def close_transport():
            closed.append(True)

        peer._worker = asyncio.create_task(worker())
        peer.transport = type("Transport", (), {"close": staticmethod(close_transport)})()
        await asyncio.sleep(0)
        with pytest.raises(RuntimeError, match="recovery failed"):
            await peer.close()
        assert peer._worker is None

    asyncio.run(scenario())
    assert closed == [True]


def test_peer_certificate_does_not_wait_for_silent_replica():
    p = Parameters("peer-fast-tail-qc", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    identities = {name: Identity.generate(name) for name in p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    expected = p.claim("committed", 1, model="a" * 64)
    cancelled = []

    async def request(name, _kind, _request, *, timeout):
        if name == "a0":
            try:
                await asyncio.sleep(timeout)
            except asyncio.CancelledError:
                cancelled.append(name)
                raise
        return identities[name].sign(expected)

    async def scenario():
        peer = object.__new__(PeerParty)
        peer.transport = type("Transport", (), {})()
        peer.transport.p = p
        peer.transport.registry = registry
        peer.transport.identity = identities["a1"]
        peer.transport.request = request
        async with asyncio.timeout(1):
            return await peer._peer_certificate(expected, identities["a1"].sign(expected),
                                                "qc", {"action": "commit"}, timeout=10)

    qc = asyncio.run(scenario())
    assert len(qc["votes"]) == p.quorum
    assert cancelled == ["a0"]


def test_peer_aggregate_shares_stop_at_context_bound_quorum():
    p = Parameters("peer-fast-shares", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    identities = {name: Identity.generate(name) for name in p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    roster_body = p.claim("roster", 1, parent="a" * 64, members=list(p.clients),
                          updates="b" * 64, late="")
    roster = certificate(roster_body,
                         [identities[name].sign(roster_body) for name in ("a1", "a2", "a3")],
                         p, registry)
    body = p.claim("aggregate-share", 1, roster=digest(roster_body), value=[1])
    cancelled = []

    async def request(name, _kind, _request, *, timeout):
        if name == "a0":
            try:
                await asyncio.sleep(timeout)
            except asyncio.CancelledError:
                cancelled.append(name)
                raise
        return identities[name].sign(body)

    async def scenario():
        peer = object.__new__(PeerParty)
        peer.transport = type("Transport", (), {})()
        peer.transport.p = p
        peer.transport.registry = registry
        peer.transport.identity = identities["a1"]
        peer.transport.request = request
        async with asyncio.timeout(1):
            return await peer._peer_aggregate_shares(
                roster, identities["a1"].sign(body), timeout=10)

    shares = asyncio.run(scenario())
    assert {share["sender"] for share in shares} == {"a1", "a2", "a3"}
    assert cancelled == ["a0"]


def test_relay_batch_checks_original_signatures_parent_and_conflicts(tmp_path):
    p = Parameters("relay-validation", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    identities = {name: Identity.from_private(json.loads(Path(configs[name]["aion-identity"]).read_text()))
                  for name in p.clients + p.aggregators}
    peer = PeerParty(configs["a0"], {name: ("127.0.0.1", 1) for name in p.aggregators[1:]})
    parent = "a" * 64
    first = identities["c0"].sign(p.claim("update", 1, parent=parent, vector=[1, 2, 3]))
    second = identities["c1"].sign(p.claim("update", 1, parent=parent, vector=[4, 5, 6]))
    path = peer_update_path(Path(configs["a0"]["aion-identity"]), p.task, "a0", 1)
    invalid = [
        {**second, "signature": "00" * 64},
        identities["a1"].sign(second["body"]),
        identities["c1"].sign({**second["body"], "parent": "b" * 64}),
        identities["c1"].sign({**second["body"], "round": 2}),
        identities["c1"].sign({**second["body"], "vector": [1]}),
        first,
    ]
    for bad in invalid:
        with pytest.raises(ProtocolError):
            peer._merge_inbox_updates(1, parent, [first, bad])
        assert not path.exists()  # Whole batch rejected before any write.
    peer._merge_inbox_updates(1, parent, [first])
    conflicting = identities["c0"].sign({**first["body"], "vector": [7, 8, 9]})
    with pytest.raises(ProtocolError, match="conflicting"):
        peer._merge_inbox_updates(1, parent, [second, conflicting])
    assert peer._read_inbox(1, parent) == [first]
    peer._merge_inbox_updates(1, parent, [second, first])
    assert peer._read_inbox(1, parent) == [first, second]


def test_inbox_sync_ignores_invalid_inventory_and_uses_honest_source(tmp_path, monkeypatch):
    p = Parameters("relay-bad-source", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    identities = {name: Identity.from_private(json.loads(Path(configs[name]["aion-identity"]).read_text()))
                  for name in p.clients + p.aggregators}
    peer = PeerParty(configs["a0"], {name: ("127.0.0.1", 1) for name in p.aggregators[1:]})
    previous = p.claim("model", 0, model=[0.0] * p.dimension, parent="", enrollment="test")
    parent = digest(previous)
    updates = [identities[name].sign(p.claim("update", 1, parent=parent, vector=[1, 2, 3]))
               for name in p.clients]
    peer._merge_inbox_updates(1, parent, updates[1:])
    queried = set()

    async def request(name, kind, transcript, *, timeout):
        assert kind == "updates"
        assert transcript == {"action": "get_updates", "round": 1, "parent": parent}
        queried.add(name)
        if name == "a3":
            raise ProtocolError("unavailable")
        batch = updates[:1]
        if name == "a1":
            batch = [{**updates[0], "signature": "00" * 64}]
        # Both outer inventory signatures are valid; only a2 relays a valid
        # original client signature. a1 must not be trusted as an author.
        return identities[name].sign(p.claim("update-inventory", 1, parent=parent, updates=batch))

    monkeypatch.setattr(peer.transport, "request", request)
    assert asyncio.run(peer.synchronize_inbox(previous)) == updates
    assert queried == set(p.aggregators[1:])


def test_inbox_sync_does_not_wait_for_stalled_peer_after_complete_inbox(tmp_path, monkeypatch):
    p = Parameters("relay-slow-source", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    _, nodes = provision(tmp_path / "identities", p)
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    identities = {name: Identity.from_private(json.loads(Path(configs[name]["aion-identity"]).read_text()))
                  for name in p.clients + p.aggregators}
    peer = PeerParty(configs["a0"], {name: ("127.0.0.1", 1) for name in p.aggregators[1:]})
    previous = p.claim("model", 0, model=[0.0] * p.dimension, parent="", enrollment="test")
    parent = digest(previous)
    updates = [identities[name].sign(p.claim("update", 1, parent=parent, vector=[1, 2, 3]))
               for name in p.clients]
    peer._merge_inbox_updates(1, parent, updates[1:])

    async def scenario():
        stalled = asyncio.Event()

        async def request(name, kind, transcript, *, timeout):
            if name == "a2":
                return identities[name].sign(p.claim(
                    "update-inventory", 1, parent=parent, updates=updates[:1]))
            await stalled.wait()
            raise ProtocolError("stalled peer was unexpectedly released")

        monkeypatch.setattr(peer.transport, "request", request)
        return await asyncio.wait_for(peer.synchronize_inbox(previous, timeout=30), timeout=2)

    assert asyncio.run(scenario()) == updates


def test_view_change_vote_can_travel_without_flower_server():
    async def scenario():
        p = Parameters("peer-view-test", ("c0", "c1"), ("a0", "a1", "a2", "a3"),
                       leader_views=True)
        identities = {name: Identity.generate(name) for name in p.aggregators}
        registry = {name: identity.public() for name, identity in identities.items()}
        prior = {"round": 0, "model": [0.0] * p.dimension}
        voter = Party(identities["a1"], p, registry, {"last_model": prior})
        votes = []

        async def leader_handler(sender, kind, transcript):
            assert sender == "a1" and kind == "vote"
            assert verify(transcript, registry, sender="a1") == p.claim(
                "view-change", 1, phase="roster", view=1, context=digest(prior))
            votes.append(transcript)

        async def voter_handler(sender, kind, transcript):
            assert sender == "a0" and kind == "timeout"
            vote = voter.view_vote(transcript)
            await voter_network.send("a0", "vote", vote)

        addresses = {name: ("127.0.0.1", 1) for name in p.aggregators}
        leader_network = PeerTransport(identities["a0"], p, registry,
                                       {k: v for k, v in addresses.items() if k != "a0"},
                                       leader_handler)
        voter_network = PeerTransport(identities["a1"], p, registry,
                                      {k: v for k, v in addresses.items() if k != "a1"},
                                      voter_handler)
        try:
            leader_address = await leader_network.start("127.0.0.1", 0)
            voter_address = await voter_network.start("127.0.0.1", 0)
            leader_network.addresses["a1"] = voter_address
            voter_network.addresses["a0"] = leader_address
            await leader_network.send("a1", "timeout", {
                "phase": "roster", "round": 1, "view": 1,
                "context": digest(prior), "previous_views": []})
            assert len(votes) == 1
        finally:
            await leader_network.close()
            await voter_network.close()

    asyncio.run(scenario())


def test_peer_decision_uses_flower_durable_state_after_server_failure(tmp_path):
    p = Parameters("peer-decision-recovery", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())

    class CrashBeforeDecision(AionWorkflow):
        model = None

        def quorum_call(self, grid, action, **kwargs):
            if action == "decide":
                self.model = kwargs["model"]
                raise RuntimeError("Flower coordinator stopped")
            return super().quorum_call(grid, action, **kwargs)

    workflow = CrashBeforeDecision(p, manifest["registry"], timeout=45.0)
    with ProcessGrid(nodes) as grid:
        with pytest.raises(RuntimeError, match="Flower coordinator stopped"):
            workflow.run(grid, 1)
    assert workflow.model is not None and "commits" in workflow.model

    names = p.clients + p.aggregators
    configs = {name: nodes[index] for index, name in enumerate(names, 1)}
    peer_config = configs["a1"]
    peers_file = tmp_path / "a1-peers.json"
    peers_file.write_text(json.dumps({name: ["127.0.0.1", 1]
                                      for name in p.aggregators if name != "a1"}))
    command = [sys.executable, "-m", "trustlessfl.peer_service",
               "--manifest", peer_config["aion-manifest"],
               "--identity", peer_config["aion-identity"],
               "--peers", str(peers_file), "--port", "0"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
    try:
        assert select.select([process.stdout], [], [], 10)[0], "peer service did not become ready"
        ready = json.loads(process.stdout.readline())
        assert ready["ready"] and ready["name"] == "a1" and ready["port"] > 0
        address = (ready["host"], ready["port"])

        async def scenario():
            sender_identity = Identity.from_private(json.loads(
                Path(configs["a0"]["aion-identity"]).read_text()))

            async def unused_handler(sender, kind, transcript):
                raise AssertionError("sender does not accept inbound requests")

            sender = PeerTransport(sender_identity, p, manifest["registry"],
                                   {name: ("127.0.0.1", 1) for name in p.aggregators if name != "a0"},
                                   unused_handler)
            sender.addresses["a1"] = address
            with pytest.raises(ProtocolError, match="peer delivery failed"):
                await sender.request("a1", "timeout", {"action": "view_vote"})
            with pytest.raises(ProtocolError, match="peer delivery failed"):
                await sender.request("a1", "qc", {"action": "share"})
            vote = await sender.request("a1", "decision", {
                "action": "decide", "model": workflow.model})
            assert verify(vote, manifest["registry"], sender="a1") == p.claim(
                "decided", 1, model=digest(workflow.model["body"]))
            return vote, configs["a1"]
        vote, a1_config = asyncio.run(scenario())
    finally:
        process.terminate()
        process.communicate(timeout=10)
    # Flower still reads the same state after the sidecar commits the model.
    request = Message(records({"action": "decide", "model": workflow.model}),
                      dst_node_id=4, message_type="query.aion")
    context = Context(1, 4, a1_config, RecordDict(), {})
    reply = client_app(request, context)
    assert not reply.has_error() and payload(reply) == vote


def test_peer_decision_quorum_survives_one_unavailable_aggregator(tmp_path):
    p = Parameters("peer-decision-quorum", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())

    class CrashBeforeDecision(AionWorkflow):
        model = None

        def quorum_call(self, grid, action, **kwargs):
            if action == "decide":
                self.model = kwargs["model"]
                raise RuntimeError("Flower coordinator stopped")
            return super().quorum_call(grid, action, **kwargs)

    workflow = CrashBeforeDecision(p, manifest["registry"], timeout=45.0)
    with ProcessGrid(nodes) as grid:
        with pytest.raises(RuntimeError, match="Flower coordinator stopped"):
            workflow.run(grid, 1)

    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name})
             for name in p.aggregators}

    def proof_path(name):
        tag = digest({"task": p.task, "party": name})
        return Path(configs[name]["aion-identity"]).parent / f"peer-decisions-{tag}.json"

    async def scenario():
        started = []
        try:
            addresses = {}
            for name in p.aggregators[:2]:
                addresses[name] = await peers[name].start("127.0.0.1", 0)
                started.append(name)
            for name in started:
                peers[name].transport.addresses.update({other: address for other, address in addresses.items()
                                                      if other != name})
            with pytest.raises(ProtocolError, match="insufficient"):
                await peers["a0"].broadcast_decision(workflow.model, timeout=1.0)

            addresses["a2"] = await peers["a2"].start("127.0.0.1", 0)
            started.append("a2")
            peers["a0"].transport.addresses["a2"] = addresses["a2"]
            decision = await peers["a0"].broadcast_decision(workflow.model, timeout=1.0)
            assert len(decision["votes"]) == p.quorum
            assert {vote["sender"] for vote in decision["votes"]} == {"a0", "a1", "a2"}
            for name in ("a0", "a1", "a2"):
                proof = json.loads(proof_path(name).read_text())["certificates"]["1"]
                assert proof["decision"]["body"] == decision["body"]
            assert not proof_path("a3").exists()
            damaged = {**decision, "votes": decision["votes"][:2]}
            with pytest.raises(ProtocolError, match="peer delivery failed"):
                await peers["a0"].transport.send("a1", "decision-qc",
                                                  {"model": workflow.model, "decision": damaged})

            original_a0_proof = proof_path("a0").read_text()
            invalid_a0_proof = json.loads(original_a0_proof)
            invalid_a0_proof["certificates"]["1"]["decision"]["votes"][0]["signature"] = "00" * 64
            proof_path("a0").write_text(json.dumps(invalid_a0_proof))
            # The late sidecar cannot collect fresh proposal votes in this
            # scenario; it must pull an existing certified decision instead.
            # A corrupted proof at a0 must not prevent a1/a2 from supplying it.
            peers["a3"].auto_complete = True

            async def unavailable_proposal(*, timeout):
                raise ProtocolError("proposal quorum unavailable")

            peers["a3"].finish_pending_model = unavailable_proposal
            addresses["a3"] = await peers["a3"].start("127.0.0.1", 0)
            started.append("a3")
            peers["a0"].transport.addresses["a3"] = addresses["a3"]
            peers["a3"].transport.addresses.update({name: addresses[name]
                                                    for name in ("a0", "a1", "a2")})
            async with asyncio.timeout(10):
                while not proof_path("a3").exists():
                    await asyncio.sleep(0.05)
            assert json.loads(proof_path("a3").read_text())["certificates"]["1"]["model"] == workflow.model
            proof_path("a0").write_text(original_a0_proof)
            replay = await peers["a0"].broadcast_decision(workflow.model, timeout=1.0)
            assert len(replay["votes"]) >= p.quorum
        finally:
            for name in started:
                await peers[name].close()

    asyncio.run(scenario())
    for name in p.aggregators:
        filename = f"state-{digest({'task': p.task, 'party': name})}.json"
        state = json.loads((Path(configs[name]["aion-identity"]).parent / filename).read_text())
        assert state["last_model"]["round"] == 1
    good_a1_proof = proof_path("a1").read_text()
    for name in ("a0", "a1"):
        damaged = json.loads(proof_path(name).read_text())
        damaged["certificates"]["1"]["decision"]["votes"][0]["signature"] = "00" * 64
        proof_path(name).write_text(json.dumps(damaged))
    # A new Flower coordinator has no local checkpoint. It reconstructs the
    # certified peer decision history before starting the next training round.
    # Two corrupted peer reports cannot form the required recovery quorum.
    with ProcessGrid(nodes) as grid:
        with pytest.raises(ProtocolError, match="insufficient valid peer recovery reports"):
            AionWorkflow(p, manifest["registry"], timeout=45.0).run(grid, 2)
        proof_path("a1").write_text(good_a1_proof)
        resumed = AionWorkflow(p, manifest["registry"], timeout=45.0).run(grid, 2)
    assert [cert["body"]["round"] for cert in resumed] == [0, 1, 2]
    assert len(resumed[1]["decisions"]["votes"]) >= p.quorum


def test_peers_finish_model_after_flower_stops_before_commit(tmp_path):
    p = Parameters("peer-commit-failover", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())

    class CrashBeforeCommit(AionWorkflow):
        model = None

        def call(self, grid, names, action, **kwargs):
            if action == "commit":
                self.model = kwargs["model"]
                raise RuntimeError("Flower stopped before commit")
            return super().call(grid, names, action, **kwargs)

    workflow = CrashBeforeCommit(p, manifest["registry"], timeout=45.0)
    with ProcessGrid(nodes) as grid:
        with pytest.raises(RuntimeError, match="Flower stopped before commit"):
            workflow.run(grid, 1)
    assert workflow.model is not None and "commits" not in workflow.model

    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name})
             for name in p.aggregators[:3]}

    async def scenario():
        started = []
        try:
            addresses = {}
            for name in peers:
                addresses[name] = await peers[name].start("127.0.0.1", 0)
                started.append(name)
            for name in peers:
                peers[name].transport.addresses.update({other: address
                                                      for other, address in addresses.items() if other != name})
            damaged = copy.deepcopy(workflow.model)
            damaged["votes"] = damaged["votes"][:p.quorum - 1]
            with pytest.raises(ProtocolError, match="insufficient"):
                await peers["a0"].finish_model(damaged, timeout=1.0)
            finalized = await peers["a0"].finish_model(workflow.model, timeout=1.0)
            assert len(finalized["commits"]["votes"]) == p.quorum
            assert len(finalized["decisions"]["votes"]) == p.quorum
            return finalized
        finally:
            for name in started:
                await peers[name].close()

    finalized = asyncio.run(scenario())
    assert finalized["body"] == workflow.model["body"]
    with ProcessGrid(nodes) as grid:
        history = AionWorkflow(p, manifest["registry"], timeout=45.0).run(grid, 2)
    assert [model["body"]["round"] for model in history] == [0, 1, 2]
    assert history[1]["body"] == finalized["body"]


@pytest.mark.parametrize("leader_views", [False, True])
def test_peers_reconstruct_missing_model_proposal_qc_after_flower_crash(tmp_path, leader_views):
    p = Parameters(f"peer-proposal-failover-{leader_views}", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), leader_views=leader_views)
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())

    class CrashAfterProposal(AionWorkflow):
        def quorum_call(self, grid, action, **kwargs):
            result = super().quorum_call(grid, action, **kwargs)
            if action == "finalize":
                raise RuntimeError("Flower lost the proposed model QC")
            return result

    with ProcessGrid(nodes) as grid:
        with pytest.raises(RuntimeError, match="lost the proposed model QC"):
            CrashAfterProposal(p, manifest["registry"], timeout=45.0).run(grid, 1)

    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name})
             for name in p.aggregators[:3]}

    async def scenario():
        try:
            addresses = {name: await peer.start("127.0.0.1", 0) for name, peer in peers.items()}
            for name, peer in peers.items():
                peer.transport.addresses.update({other: address for other, address in addresses.items()
                                                 if other != name})
            with pytest.raises(ProtocolError, match="peer delivery failed"):
                await peers["a0"].transport.request("a1", "proposal",
                                                     {"action": "proposal_vote", "candidate": "0" * 64},
                                                     timeout=1.0)
            model = await peers["a0"].finish_pending_model(timeout=1.0)
            assert len(model["votes"]) == p.quorum
            assert len(model["commits"]["votes"]) == p.quorum
            assert len(model["decisions"]["votes"]) == p.quorum
            return model
        finally:
            for peer in peers.values():
                await peer.close()

    recovered = asyncio.run(scenario())
    with ProcessGrid(nodes) as grid:
        history = AionWorkflow(p, manifest["registry"], timeout=45.0).run(grid, 2)
    assert [model["body"]["round"] for model in history] == [0, 1, 2]
    assert history[1]["body"] == recovered["body"]


def test_peer_sidecar_auto_completes_quorum_proposal_without_flower(tmp_path):
    p = Parameters("peer-auto-proposal-failover", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())

    class CrashAfterProposal(AionWorkflow):
        def quorum_call(self, grid, action, **kwargs):
            result = super().quorum_call(grid, action, **kwargs)
            if action == "finalize":
                raise RuntimeError("Flower lost the proposed model QC")
            return result

    with ProcessGrid(nodes) as grid:
        with pytest.raises(RuntimeError, match="lost the proposed model QC"):
            CrashAfterProposal(p, manifest["registry"], timeout=45.0).run(grid, 1)

    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name},
                             auto_complete=name == "a0")
             for name in p.aggregators[:3]}
    proof_path = Path(configs["a0"]["aion-identity"]).parent / (
        f"peer-decisions-{digest({'task': p.task, 'party': 'a0'})}.json")

    async def scenario():
        try:
            addresses = {name: await peer.start("127.0.0.1", 0) for name, peer in peers.items()}
            for name, peer in peers.items():
                peer.transport.addresses.update({other: address for other, address in addresses.items()
                                                 if other != name})
            for _ in range(100):
                if proof_path.exists():
                    return
                await asyncio.sleep(0.1)
            raise AssertionError("sidecar did not automatically finish a quorum proposal")
        finally:
            for peer in peers.values():
                await peer.close()

    asyncio.run(scenario())
    stored = json.loads(proof_path.read_text())["certificates"]["1"]
    assert len(stored["model"]["votes"]) >= p.quorum
    assert len(stored["model"]["commits"]["votes"]) >= p.quorum
    assert len(stored["decision"]["votes"]) >= p.quorum


@pytest.mark.parametrize("leader_views", [False, True])
def test_peers_recover_locked_roster_before_flower_share_phase(tmp_path, leader_views):
    p = Parameters(f"peer-roster-failover-{leader_views}", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), leader_views=leader_views)
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())

    class CrashAfterRoster(AionWorkflow):
        def quorum_call(self, grid, action, **kwargs):
            result = super().quorum_call(grid, action, **kwargs)
            if action == "prepare":
                raise RuntimeError("Flower lost the roster QC")
            return result

    with ProcessGrid(nodes) as grid:
        with pytest.raises(RuntimeError, match="lost the roster QC"):
            CrashAfterRoster(p, manifest["registry"], timeout=45.0).run(grid, 1)

    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name})
             for name in p.aggregators[:3]}

    async def scenario():
        try:
            addresses = {name: await peer.start("127.0.0.1", 0) for name, peer in peers.items()}
            for name, peer in peers.items():
                peer.transport.addresses.update({other: address for other, address in addresses.items()
                                                 if other != name})
            with pytest.raises(ProtocolError, match="peer delivery failed"):
                await peers["a0"].transport.request("a1", "roster",
                                                     {"action": "roster_vote", "candidate": "0" * 64},
                                                     timeout=1.0)
            roster = await peers["a0"].recover_roster(timeout=1.0)
            assert len(roster["votes"]) == p.quorum
            if leader_views:
                assert len(roster["commits"]["votes"]) == p.quorum
            invalid = copy.deepcopy(roster)
            invalid["votes"] = invalid["votes"][:p.quorum - 1]
            with pytest.raises(ProtocolError, match="peer delivery failed"):
                await peers["a0"].transport.request("a1", "qc",
                                                     {"action": "share", "roster": invalid},
                                                     timeout=1.0)
            return roster
        finally:
            for peer in peers.values():
                await peer.close()

    roster = asyncio.run(scenario())
    truncated = copy.deepcopy(roster)
    truncated["votes"] = truncated["votes"][:p.quorum - 1]
    with pytest.raises(ProtocolError):
        process_local_request(configs["a0"], {"action": "share", "roster": truncated})
    share = process_local_request(configs["a0"], {"action": "share", "roster": roster})
    assert share["body"]["roster"] == digest(roster["body"])
    with ProcessGrid(nodes) as grid:
        history = AionWorkflow(p, manifest["registry"], timeout=45.0).run(grid, 1)
    assert history[-1]["body"]["round"] == 1


@pytest.mark.parametrize("auto", [False, True])
def test_peers_finish_locked_roster_through_model_decision_without_flower(tmp_path, auto):
    p = Parameters(f"peer-roster-to-model-{auto}", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())

    class CrashAfterRoster(AionWorkflow):
        def quorum_call(self, grid, action, **kwargs):
            result = super().quorum_call(grid, action, **kwargs)
            if action == "prepare":
                raise RuntimeError("Flower stopped before roster release")
            return result

    with ProcessGrid(nodes) as grid:
        with pytest.raises(RuntimeError, match="before roster release"):
            CrashAfterRoster(p, manifest["registry"], timeout=45.0).run(grid, 1)

    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name},
                             auto_complete=auto and name == "a0")
             for name in p.aggregators[:3]}
    proof_path = Path(configs["a0"]["aion-identity"]).parent / (
        f"peer-decisions-{digest({'task': p.task, 'party': 'a0'})}.json")

    async def scenario():
        try:
            addresses = {name: await peer.start("127.0.0.1", 0) for name, peer in peers.items()}
            for name, peer in peers.items():
                peer.transport.addresses.update({other: address for other, address in addresses.items()
                                                 if other != name})
            if not auto:
                finalized = await peers["a0"].finish_pending_roster(timeout=1.0)
                assert len(finalized["votes"]) == p.quorum
                assert len(finalized["commits"]["votes"]) == p.quorum
                assert len(finalized["decisions"]["votes"]) == p.quorum
            else:
                for _ in range(300):
                    if proof_path.exists():
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise AssertionError("sidecar did not finish the locked roster")
        finally:
            for peer in peers.values():
                await peer.close()

    asyncio.run(scenario())
    proof = json.loads(proof_path.read_text())["certificates"]["1"]
    assert len(proof["model"]["votes"]) == p.quorum
    with ProcessGrid(nodes) as grid:
        history = AionWorkflow(p, manifest["registry"], timeout=45.0).run(grid, 2)
    assert [model["body"]["round"] for model in history] == [0, 1, 2]
    assert history[1]["body"] == proof["model"]["body"]


@pytest.mark.parametrize("auto", [False, True])
def test_peer_model_view_change_after_initial_leader_disappears(tmp_path, auto):
    p = Parameters(f"peer-model-view-change-{auto}", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), leader_views=True)
    manifest_path, nodes = provision(tmp_path / "identities", p)
    manifest = json.loads(manifest_path.read_text())

    class CrashAfterRoster(AionWorkflow):
        def quorum_call(self, grid, action, **kwargs):
            result = super().quorum_call(grid, action, **kwargs)
            if action == "prepare":
                raise RuntimeError("Flower stopped after roster votes")
            return result

    with ProcessGrid(nodes) as grid:
        with pytest.raises(RuntimeError, match="after roster votes"):
            CrashAfterRoster(p, manifest["registry"], timeout=45.0).run(grid, 1)

    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    # a0, the view-zero leader, is offline. The remaining three form n-f.
    peers = {name: PeerParty(configs[name], {other: ("127.0.0.1", 1)
                                            for other in p.aggregators if other != name},
                             auto_complete=auto and name == "a1", recovery_delay=0.0)
             for name in p.aggregators[1:]}
    proof_path = Path(configs["a1"]["aion-identity"]).parent / (
        f"peer-decisions-{digest({'task': p.task, 'party': 'a1'})}.json")

    async def scenario():
        try:
            addresses = {name: await peer.start("127.0.0.1", 0) for name, peer in peers.items()}
            for name, peer in peers.items():
                peer.transport.addresses.update({other: address for other, address in addresses.items()
                                                 if other != name})
            if auto:
                for _ in range(300):
                    if proof_path.exists():
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise AssertionError("leader-view sidecar did not finish after view change")
                proof = json.loads(proof_path.read_text())["certificates"]["1"]
                finalized = {**proof["model"], "decisions": proof["decision"]}
            else:
                roster = await peers["a1"].recover_roster(timeout=2.0)
                invalid = copy.deepcopy(roster)
                invalid["votes"] = invalid["votes"][:p.quorum - 1]
                with pytest.raises(ProtocolError, match="peer delivery failed"):
                    await peers["a1"].transport.request("a2", "timeout", {
                        "action": "view_vote", "phase": "model", "round": 1,
                        "view": 1, "context": digest(roster["body"]),
                        "previous_views": [], "roster": invalid}, timeout=2.0)
                finalized = await peers["a1"].finish_pending_roster(timeout=2.0)
            assert finalized["consensus"]["view"] == 1
            assert len(finalized["consensus"]["view_qc"]["votes"]) == p.quorum
            assert len(finalized["commits"]["votes"]) == p.quorum
            assert len(finalized["decisions"]["votes"]) == p.quorum
            return finalized
        finally:
            for peer in peers.values():
                await peer.close()

    recovered = asyncio.run(scenario())
    with ProcessGrid(nodes) as grid:
        history = AionWorkflow(p, manifest["registry"], timeout=45.0).run(grid, 2)
    assert [model["body"]["round"] for model in history] == [0, 1, 2]
    assert history[1]["body"] == recovered["body"]

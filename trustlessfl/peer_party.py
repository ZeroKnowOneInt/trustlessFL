"""Peer model-tail recovery against the same durable state as Flower ClientApp.

Peers reconcile client-signed masked updates, read locked roster/model votes,
and apply certified public transitions. A certified roster can trigger only
its own aggregate-share release. Model view-change requires a locked roster;
peers cannot request individual shares or training.
This is not a pacemaker and does not replace Flower's ServerApp.
"""

from __future__ import annotations

import asyncio
import copy
import fcntl
import json
import math
import os
from contextlib import suppress
from pathlib import Path

from .client_app import peer_decision_path, peer_update_path, process_local_request, save_state
from .crypto import Identity, ProtocolError, digest, verify
from .numeric import OUTPUT_MODULUS
from .mgf_wire import validate_mgf_state
from .mgf_selection import admission_bound, check_update_probe, select_probes
from .peer_transport import PeerTransport
from .protocol import (Parameters, certificate, check_certificate,
                       check_finalized_model, check_finalized_roster)

PEER_ACTIONS = {"qc": frozenset({"roster_commit", "commit", "share"}),
                "decision": frozenset({"decide"}),
                "proposal": frozenset({"proposal_vote", "finalize"}),
                "roster": frozenset({"roster_vote"}),
                "genesis": frozenset({"genesis_vote"})}


class PeerParty:
    """Optional aggregator sidecar sharing Flower's file-locked Party state."""

    def __init__(self, node_config: dict, addresses: dict[str, tuple[str, int]],
                 *, auto_complete: bool = False, recovery_delay: float = 5.0):
        if (type(auto_complete) is not bool or type(recovery_delay) not in (int, float)
                or not math.isfinite(recovery_delay)
                or not 0 <= recovery_delay <= 300):
            raise ProtocolError("invalid peer recovery configuration")
        manifest = json.loads(Path(str(node_config["aion-manifest"])).read_text())
        if manifest.get("research-mode") is not True:
            raise ProtocolError("peer sidecar requires research opt-in")
        p = Parameters.from_dict(manifest["parameters"])
        identity = Identity.from_private(json.loads(Path(str(node_config["aion-identity"])).read_text()))
        if identity.name not in p.aggregators:
            raise ProtocolError("peer sidecar requires aggregator identity")
        if any(key in node_config for key in ("mnist-shard", "endpoint-shard")):
            raise ProtocolError("peer sidecar must not have training data")
        self.node_config = dict(node_config)
        self.transport = PeerTransport(identity, p, manifest["registry"], addresses, self._handle)
        self.auto_complete = auto_complete
        self.recovery_delay = recovery_delay
        self._worker: asyncio.Task | None = None
        self._completed_rounds: set[int] = set()
        self._roster_seen_at: dict[int, float] = {}
        self._updates_seen_at: dict[int, float] = {}
        self._peer_timeout = 3.0
        self._recovery_attempted = False
        self._recovery_stage = "idle"
        self._recovery_failures: list[tuple[str, str]] = []

    def _record_recovery_failure(self, stage: str, exc: ProtocolError) -> None:
        # Bounded, local-only diagnostics for an otherwise silently retried
        # pacemaker attempt. Never include request bodies or client updates.
        self._recovery_failures.append((stage, str(exc)))
        del self._recovery_failures[:-16]

    async def _handle(self, sender: str, kind: str, transcript: dict) -> dict:
        if kind == "decision-qc":
            return await self._install_decision_proof(transcript)
        if kind == "decision-proof":
            if (sender not in self.transport.p.aggregators
                    or set(transcript) != {"action", "round"}
                    or transcript["action"] != "get_decision_proof"):
                raise ProtocolError("invalid peer decision proof query")
            return await asyncio.to_thread(self._decision_proof_response, transcript["round"])
        if kind == "client-update":
            return await asyncio.to_thread(self._store_client_update, sender, transcript)
        if kind == "updates":
            if sender not in self.transport.p.aggregators or transcript.get("action") != "get_updates":
                raise ProtocolError("invalid peer update query")
            return await asyncio.to_thread(self._update_inventory, transcript)
        if kind == "hotstuff":
            if sender not in self.transport.p.aggregators or transcript.get("action") != "hotstuff":
                raise ProtocolError("invalid peer HotStuff request")
            return await asyncio.to_thread(process_local_request, self.node_config, transcript)
        if kind == "mgf-admit":
            if (sender not in self.transport.p.aggregators or not self.transport.p.mgf_enabled
                    or transcript.get("action") != "mgf_admit"):
                raise ProtocolError("invalid peer MGF admission request")
            return await asyncio.to_thread(process_local_request, self.node_config, transcript)
        if kind == "mgf-cohort":
            if (sender not in self.transport.p.aggregators
                    or not self.transport.p.mgf_percentile
                    or transcript.get("action") not in ("mgf_cohort_vote", "mgf_cohort_share", "mgf_cohort_norm")):
                raise ProtocolError("invalid peer MGF cohort norm request")
            return await asyncio.to_thread(process_local_request, self.node_config, transcript)
        if kind == "roster" and transcript.get("action") == "prepare":
            p, registry = self.transport.p, self.transport.registry
            if p.privacy_groups or p.ema_weight or p.mgf_enabled:
                raise ProtocolError("peer update preparation requires fixed full cohort")
            model = check_finalized_model(transcript.get("model"), p, registry)
            # A relay is not an update author: verify every original client
            # signature and parent before admitting the batch to durable state.
            await asyncio.to_thread(self._merge_inbox_updates, model["round"] + 1,
                                    digest(model), transcript.get("updates"))
            updates = await asyncio.to_thread(self._inbox_updates, model)
            if transcript.get("updates") != updates:
                raise ProtocolError("peer roster differs from locally delivered updates")
            return await asyncio.to_thread(process_local_request, self.node_config, transcript)
        action = transcript.get("action")
        if kind == "timeout":
            if action != "view_vote" or transcript.get("phase") != "model":
                raise ProtocolError("peer timeout cannot change this phase")
            p, registry = self.transport.p, self.transport.registry
            roster = check_finalized_roster(transcript.get("roster"), p, registry)
            status_envelope = await asyncio.to_thread(process_local_request, self.node_config,
                                                      {"action": "roster_proof"})
            status = verify(status_envelope, registry, sender=self.transport.identity.name)
            if (status.get("candidate") != roster or transcript.get("round") != roster["round"]
                    or transcript.get("context") != digest(roster)):
                raise ProtocolError("peer timeout differs from committed local roster")
            return await asyncio.to_thread(process_local_request, self.node_config, transcript)
        if kind not in PEER_ACTIONS or action not in PEER_ACTIONS[kind]:
            raise ProtocolError("peer action is not a certified public transition")
        return await asyncio.to_thread(process_local_request, self.node_config, transcript)

    async def start(self, host: str, port: int) -> tuple[str, int]:
        address = await self.transport.start(host, port)
        if self.auto_complete:
            self._worker = asyncio.create_task(self._auto_complete_pending())
        return address

    async def close(self) -> None:
        try:
            if self._worker is not None:
                self._worker.cancel()
                with suppress(asyncio.CancelledError):
                    await self._worker
        finally:
            self._worker = None
            await self.transport.close()

    async def _peer_certificate(self, expected: dict, local_vote: dict | None, kind: str,
                                request: dict, *, timeout: float) -> dict:
        """Stop waiting for absent peers once a valid signed QC exists."""
        p, registry = self.transport.p, self.transport.registry

        async def ask(name: str) -> dict | None:
            try:
                return await self.transport.request(name, kind, request, timeout=timeout)
            except ProtocolError:
                return None

        votes = [local_vote] if local_vote is not None else []
        tasks = {asyncio.create_task(ask(name)) for name in p.aggregators
                 if name != self.transport.identity.name}
        try:
            while True:
                try:
                    return certificate(expected, votes, p, registry)
                except ProtocolError:
                    if not tasks:
                        raise
                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                votes.extend(vote for task in done if (vote := task.result()) is not None)
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _peer_aggregate_shares(self, roster: dict, local_share: dict,
                                     *, timeout: float) -> list[dict]:
        """Collect n-f context-bound shares, enough for f+1 honest shares."""
        p, registry = self.transport.p, self.transport.registry
        roster_body = check_finalized_roster(roster, p, registry)
        kind = "mgf-aggregate-share" if p.mgf_enabled else "aggregate-share"
        expected = p.claim(kind, roster_body["round"])
        roster_hash = digest(roster_body)

        def valid(name: str, envelope: dict) -> bool:
            body = verify(envelope, registry, sender=name)
            return (isinstance(body, dict)
                    and all(body.get(key) == value for key, value in expected.items())
                    and body.get("roster") == roster_hash)

        if not valid(self.transport.identity.name, local_share):
            raise ProtocolError("local aggregate share differs from certified roster")

        async def ask(name: str) -> dict | None:
            try:
                reply = await self.transport.request(
                    name, "qc", {"action": "share", "roster": roster}, timeout=timeout)
                return reply if valid(name, reply) else None
            except (ProtocolError, KeyError, TypeError):
                return None

        shares = [local_share]
        tasks = {asyncio.create_task(ask(name)) for name in p.aggregators
                 if name != self.transport.identity.name}
        try:
            while tasks and len(shares) < p.quorum:
                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                shares.extend(share for task in done if (share := task.result()) is not None)
            if len(shares) < p.quorum:
                raise ProtocolError("aggregate share quorum unavailable")
            # With n >= 3f+1, an n-f set contains at least f+1 honest
            # shares. Party.finalize independently verifies both VSS families
            # and reconstructs only from those valid shares.
            return shares[:p.quorum]
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _auto_complete_pending(self) -> None:
        """Retry pending work, including rounds after an earlier peer decision."""
        while True:
            before = len(self._completed_rounds)
            self._recovery_attempted = False
            await self._auto_complete_once()
            if len(self._completed_rounds) > before:
                self._peer_timeout = 3.0
            elif self._recovery_attempted:
                self._peer_timeout = min(self._peer_timeout * 2,
                                         float.fromhex("0x1.0p+900"))
            await asyncio.sleep(1.0)

    async def _auto_complete_once(self) -> None:
        p, registry = self.transport.p, self.transport.registry
        # A completed proposal remains in durable state. Do not let that
        # successful read hide a newer roster or the next inbox indefinitely.
        for action, finish in (("proposal_proof", self.finish_pending_model),
                               ("roster_proof", self.finish_pending_roster)):
            try:
                status_envelope = await asyncio.to_thread(process_local_request, self.node_config,
                                                          {"action": action})
                status = verify(status_envelope, registry,
                                sender=self.transport.identity.name)
                round_id = status.get("round")
                if type(round_id) is int and round_id not in self._completed_rounds:
                    if action == "roster_proof":
                        now = asyncio.get_running_loop().time()
                        seen_at = self._roster_seen_at.setdefault(round_id, now)
                        if now - seen_at < self.recovery_delay:
                            return
                    self._recovery_attempted = True
                    try:
                        self._recovery_stage = action
                        finalized = await finish(timeout=self._peer_timeout)
                    except ProtocolError as exc:
                        self._record_recovery_failure(action, exc)
                        if action == "proposal_proof":
                            try:
                                self._recovery_stage = "decision-proof"
                                await self.synchronize_decision_proof(
                                    round_id, timeout=self._peer_timeout)
                            except ProtocolError as proof_exc:
                                self._record_recovery_failure("decision-proof", proof_exc)
                            else:
                                self._completed_rounds.add(round_id)
                                self._recovery_stage = "idle"
                                return
                        raise
                    if finalized["body"]["round"] != round_id:
                        raise ProtocolError("auto-completed another pending round")
                    self._completed_rounds.add(round_id)
                    self._recovery_stage = "idle"
                    return
            except ProtocolError as exc:
                # Missing evidence or unavailable peers: keep durable locks
                # and try another recovery stage before the next retry.
                self._record_recovery_failure(action, exc)
        if (not p.leader_views and not p.privacy_groups and not p.ema_weight
                and (not p.mgf_enabled or p.hotstuff)):
            try:
                model_envelope = await asyncio.to_thread(
                    process_local_request, self.node_config, {"action": "model_status"})
                model_status = verify(model_envelope, registry, sender=self.transport.identity.name)
                previous = model_status["model"]
                round_id = previous["round"] + 1
                if round_id not in self._completed_rounds:
                    partial = await asyncio.to_thread(self._read_inbox, round_id, digest(previous))
                    try:
                        self._recovery_stage = "synchronize-inbox"
                        await self.synchronize_inbox(previous, timeout=self._peer_timeout)
                    except ProtocolError as exc:
                        self._record_recovery_failure("synchronize-inbox", exc)
                        if partial:
                            self._recovery_attempted = True
                        raise
                    now = asyncio.get_running_loop().time()
                    seen_at = self._updates_seen_at.setdefault(round_id, now)
                    if now - seen_at >= self.recovery_delay:
                        self._recovery_attempted = True
                        self._recovery_stage = "prepare-from-inbox"
                        finalized = await self.prepare_from_inbox(timeout=self._peer_timeout)
                        if finalized["body"]["round"] != round_id:
                            raise ProtocolError("auto-prepared another update round")
                        self._completed_rounds.add(round_id)
                        self._recovery_stage = "idle"
            except (ProtocolError, KeyError, TypeError) as exc:
                if isinstance(exc, ProtocolError):
                    self._record_recovery_failure(self._recovery_stage, exc)
                pass
        self._recovery_stage = "idle"

    def _proof_paths(self) -> tuple[Path, Path]:
        p, identity = self.transport.p, self.transport.identity
        path = peer_decision_path(Path(str(self.node_config["aion-identity"])),
                                  p.task, identity.name)
        return path, path.with_suffix(".lock")

    def _decision_proof_response(self, round_id: int) -> dict:
        """Return only a locally stored, fully certified public decision."""
        if type(round_id) is not int or round_id < 1:
            raise ProtocolError("invalid peer decision proof round")
        p, registry = self.transport.p, self.transport.registry
        path, lock_path = self._proof_paths()
        with lock_path.open("a+b") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            if not path.exists():
                raise ProtocolError("peer decision proof unavailable")
            store = json.loads(path.read_text())
        if (not isinstance(store, dict) or store.get("task") != p.task
                or not isinstance(store.get("certificates"), dict)):
            raise ProtocolError("invalid peer decision proof store")
        proof = store["certificates"].get(str(round_id))
        if not isinstance(proof, dict):
            raise ProtocolError("peer decision proof unavailable")
        model, decision = proof.get("model"), proof.get("decision")
        body = check_finalized_model(model, p, registry)
        expected = p.claim("decided", round_id, model=digest(body))
        if body["round"] != round_id or not isinstance(decision, dict) \
                or decision.get("body") != expected:
            raise ProtocolError("peer decision proof differs from round")
        certificate(expected, decision.get("votes", []), p, registry)
        return self.transport.identity.sign(p.claim(
            "decision-proof", round_id, model=model, decision=decision))

    async def synchronize_decision_proof(self, round_id: int, *, timeout: float = 10.0) -> dict:
        """Pull a certified decision; local application locks still gate install."""
        if type(round_id) is not int or round_id < 1:
            raise ProtocolError("invalid peer decision proof round")
        p, registry = self.transport.p, self.transport.registry

        async def ask(name: str) -> dict | None:
            try:
                reply = await self.transport.request(
                    name, "decision-proof",
                    {"action": "get_decision_proof", "round": round_id}, timeout=timeout)
                claim = verify(reply, registry, sender=name)
                model, decision = claim["model"], claim["decision"]
                if claim != p.claim("decision-proof", round_id,
                                    model=model, decision=decision):
                    raise ProtocolError("invalid peer decision proof response")
                body = check_finalized_model(model, p, registry)
                expected = p.claim("decided", round_id, model=digest(body))
                if (body["round"] != round_id or not isinstance(decision, dict)
                        or decision.get("body") != expected):
                    raise ProtocolError("peer decision proof differs from round")
                certificate(expected, decision.get("votes", []), p, registry)
                await self._install_decision_proof({"model": model, "decision": decision})
                return {"model": model, "decision": decision}
            except (ProtocolError, KeyError, TypeError, ValueError, AttributeError):
                return None

        tasks = {asyncio.create_task(ask(name)) for name in p.aggregators
                 if name != self.transport.identity.name}
        try:
            while tasks:
                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if (proof := task.result()) is not None:
                        return proof
            raise ProtocolError("certified peer decision proof unavailable")
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    def _store_client_update(self, sender: str, transcript: dict) -> dict:
        """Durably store only an authenticated update, never a plaintext delta."""
        p = self.transport.p
        if sender not in p.clients or transcript.get("action") != "deliver_update":
            raise ProtocolError("invalid client update delivery")
        update = transcript.get("update")
        body = self._validate_client_update(update, sender=sender)
        self._merge_inbox_updates(body["round"], body["parent"], [update])
        return self.transport.identity.sign(p.claim(
            "update-received", body["round"], client=sender, update=digest(update)))

    def _validate_client_update(self, update: dict, *, sender: str | None = None) -> dict:
        p, registry = self.transport.p, self.transport.registry
        if (not isinstance(update, dict) or not isinstance(update.get("sender"), str)
                or update["sender"] not in p.clients):
            raise ProtocolError("invalid client update author")
        body = verify(update, registry, sender=sender or update["sender"])
        if not isinstance(body, dict):
            raise ProtocolError("invalid signed client update")
        round_id = body.get("round")
        if type(round_id) is not int or round_id < 1:
            raise ProtocolError("invalid delivered update round")
        expected = p.claim("update", round_id)
        if (any(body.get(key) != value for key, value in expected.items())
                or not isinstance(body.get("parent"), str) or len(body["parent"]) != 64
                or any(char not in "0123456789abcdef" for char in body["parent"])):
            raise ProtocolError("delivered update is outside this task")
        vector = body.get("vector")
        if p.mgf_enabled and not p.mgf_projection:
            # The signed bounded-mask vector is deliberately not a modular
            # residue. A relay cannot decrypt recipient-specific share
            # packets; each voting aggregator checks those before prepare.
            max_integer = p.codec.max_integer * 2 + 1
            if (not isinstance(vector, list) or len(vector) != p.dimension
                    or any(type(value) is not int or abs(value) > max_integer
                           for value in vector)
                    or not isinstance(body.get("mgf"), dict)):
                raise ProtocolError("invalid delivered MGF masked vector")
        elif (not isinstance(vector, list) or len(vector) != p.dimension
              or any(type(value) is not int or not 0 <= value < OUTPUT_MODULUS
                     for value in vector)):
            raise ProtocolError("invalid delivered masked vector")
        if p.mgf_projection:
            probe = body.get("mgf_vector")
            if (not isinstance(probe, list) or len(probe) != p.mgf_dimension
                    or any(type(value) is not int or abs(value) > p.codec.max_integer * 2 + 1
                           for value in probe)
                    or not isinstance(body.get("mgf"), dict)):
                raise ProtocolError("invalid delivered MGF projection")
        if p.mgf_percentile:
            check_update_probe(p, registry, body)
        return body

    def _merge_inbox_updates(self, round_id: int, parent: str, updates: list[dict]) -> None:
        """Validate a whole relay batch before an atomic, conflict-preserving merge."""
        p = self.transport.p
        if not isinstance(updates, list) or len(updates) > len(p.clients):
            raise ProtocolError("invalid peer update batch")
        incoming = {}
        for update in updates:
            body = self._validate_client_update(update)
            name = update["sender"]
            if body["round"] != round_id or body["parent"] != parent or name in incoming:
                raise ProtocolError("peer update batch has wrong context or duplicate author")
            incoming[name] = update
        if not incoming:
            return
        identity_path = Path(str(self.node_config["aion-identity"]))
        path = peer_update_path(identity_path, p.task, self.transport.identity.name, round_id)
        lock_path = path.with_suffix(".lock")
        with lock_path.open("a+b") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = json.loads(path.read_text()) if path.exists() else {
                "task": p.task, "round": round_id, "updates": {}}
            if (not isinstance(state, dict) or state.get("task") != p.task
                    or state.get("round") != round_id or not isinstance(state.get("updates"), dict)):
                raise ProtocolError("invalid peer update store")
            for name, update in incoming.items():
                prior = state["updates"].get(name)
                if prior is not None and prior != update:
                    raise ProtocolError("conflicting signed client update")
            if any(name not in state["updates"] for name in incoming):
                state["updates"].update(incoming)
                save_state(path, state)

    def _read_inbox(self, round_id: int, parent: str) -> list[dict]:
        """Return a validated partial inbox, ordered by the pinned client roster."""
        p = self.transport.p
        if (type(round_id) is not int or round_id < 1 or not isinstance(parent, str)
                or len(parent) != 64 or any(c not in "0123456789abcdef" for c in parent)):
            raise ProtocolError("invalid peer inbox context")
        identity_path = Path(str(self.node_config["aion-identity"]))
        path = peer_update_path(identity_path, p.task, self.transport.identity.name, round_id)
        if not path.exists():
            return []
        lock_path = path.with_suffix(".lock")
        with lock_path.open("a+b") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
            state = json.loads(path.read_text())
        if (not isinstance(state, dict) or state.get("task") != p.task or state.get("round") != round_id
                or not isinstance(state.get("updates"), dict)
                or not set(state["updates"]).issubset(p.clients)):
            raise ProtocolError("invalid peer update store")
        updates = []
        for name in p.clients:
            if name not in state["updates"]:
                continue
            update = state["updates"][name]
            body = self._validate_client_update(update, sender=name)
            if body["round"] != round_id or body["parent"] != parent:
                raise ProtocolError("peer update is not trained on local committed model")
            updates.append(update)
        return updates

    def _inbox_updates(self, previous: dict) -> list[dict]:
        """Select independently valid signed updates for this exact model."""
        p = self.transport.p
        if p.privacy_groups or p.ema_weight:
            raise ProtocolError("peer inbox preparation excludes privacy groups and EMA")
        updates = self._read_inbox(previous["round"] + 1, digest(previous))
        if p.mgf_enabled:
            state = validate_mgf_state(p, previous.get("mgf_state"))
            accepted = [update for update in updates
                        if update["body"].get("mgf", {}).get("alpha") == state["alpha"]
                        and p.mgf_codec.accepts(update["body"]["mgf_vector" if p.mgf_projection else "vector"], admission_bound(p, state))]
            if len(accepted) < 2:
                raise ProtocolError("incomplete MGF peer update inbox")
            return accepted
        if len(updates) != len(p.clients):
            raise ProtocolError("incomplete peer update inbox")
        return updates

    def _update_inventory(self, request: dict) -> dict:
        round_id, parent = request.get("round"), request.get("parent")
        updates = self._read_inbox(round_id, parent)
        return self.transport.identity.sign(self.transport.p.claim(
            "update-inventory", round_id, parent=parent, updates=updates))

    async def synchronize_inbox(self, previous: dict, *, timeout: float = 10.0,
                                force_fetch: bool = False) -> list[dict]:
        """Fetch missing original client signatures from authenticated aggregators.

        Different clients may reach different quorums. Their honest holders
        can relay the signed updates; an aggregator signature alone never
        authorizes an update. Conflicting client signatures remain an error.
        """
        if type(force_fetch) is not bool:
            raise ProtocolError("invalid peer inbox synchronization mode")
        if not force_fetch:
            try:
                return await asyncio.to_thread(self._inbox_updates, previous)
            except ProtocolError:
                pass
        p, registry = self.transport.p, self.transport.registry
        round_id, parent = previous["round"] + 1, digest(previous)

        async def fetch(name: str) -> None:
            try:
                reply = await self.transport.request(name, "updates", {
                    "action": "get_updates", "round": round_id, "parent": parent}, timeout=timeout)
                body = verify(reply, registry, sender=name)
                if (not isinstance(body, dict) or body != p.claim(
                        "update-inventory", round_id, parent=parent, updates=body.get("updates"))):
                    raise ProtocolError("invalid peer update inventory")
                await asyncio.to_thread(self._merge_inbox_updates, round_id, parent, body["updates"])
            except ProtocolError:
                # An unavailable or invalid source cannot suppress another
                # peer's valid client-signed inventory.
                return

        tasks = {asyncio.create_task(fetch(name)) for name in self.transport.addresses}
        try:
            while tasks:
                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
                if not force_fetch:
                    try:
                        # A slow or faulty peer cannot delay recovery after all
                        # original client signatures are already durable locally.
                        return await asyncio.to_thread(self._inbox_updates, previous)
                    except ProtocolError:
                        continue
            return await asyncio.to_thread(self._inbox_updates, previous)
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def prepare_from_inbox(self, *, timeout: float = 10.0) -> dict:
        """Start a peer round from signed updates sent by Flower clients.

        The training still happened in Flower ClientApp. Fixed-cohort legacy
        rounds require every update locally; dynamic MGF rosters require
        HotStuff and individually valid client signatures, but a peer may
        verify an update supplied in a HotStuff proposal by another peer.
        """
        p, registry = self.transport.p, self.transport.registry
        if (p.leader_views or p.privacy_groups or p.ema_weight
                or (p.mgf_enabled and not p.hotstuff)):
            raise ProtocolError("peer inbox preparation needs nonleader cohort or MGF HotStuff")
        status_envelope = await asyncio.to_thread(process_local_request, self.node_config,
                                                  {"action": "model_status"})
        status = verify(status_envelope, registry, sender=self.transport.identity.name)
        previous = status.get("model")
        if (not isinstance(previous, dict) or status != p.claim(
                "model-status", previous.get("round"), model=previous)):
            raise ProtocolError("invalid local model status")
        if previous["round"] == 0:
            local_vote = await asyncio.to_thread(process_local_request, self.node_config,
                                                 {"action": "genesis_vote"})

            async def genesis(name: str) -> dict | None:
                try:
                    return await self.transport.request(name, "genesis",
                                                        {"action": "genesis_vote"}, timeout=timeout)
                except ProtocolError:
                    return None

            replies = await asyncio.gather(*(genesis(name) for name in p.aggregators
                                             if name != self.transport.identity.name))
            model = certificate(previous, [local_vote, *(v for v in replies if v is not None)],
                                p, registry)
        else:
            proof_path, lock_path = self._proof_paths()
            with lock_path.open("a+b") as lock:
                os.chmod(lock_path, 0o600)
                fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
                if not proof_path.exists():
                    raise ProtocolError("no durable peer decision proof for prior model")
                store = json.loads(proof_path.read_text())
            if store.get("task") != p.task or not isinstance(store.get("certificates"), dict):
                raise ProtocolError("invalid peer decision proof store")
            proof = store["certificates"].get(str(previous["round"]))
            if not isinstance(proof, dict):
                raise ProtocolError("prior peer decision proof is missing")
            model = copy.deepcopy(proof["model"])
            prior_body = check_finalized_model(model, p, registry)
            expected_decision = p.claim("decided", previous["round"], model=digest(prior_body))
            decision = proof.get("decision")
            if (prior_body != previous or not isinstance(decision, dict)
                    or decision.get("body") != expected_decision):
                raise ProtocolError("prior peer decision proof differs from local model")
            certificate(expected_decision, decision.get("votes", []), p, registry)
        updates = await self.synchronize_inbox(previous, timeout=timeout)
        if p.mgf_enabled:
            try:
                updates = await self._admit_mgf_updates(model, updates, timeout=timeout)
            except ProtocolError:
                # Two norm-valid inbox entries can include an invalid share.
                # Fetch other peers' signed updates before declaring the
                # dynamic roster impossible.
                updates = await self.synchronize_inbox(
                    previous, timeout=timeout, force_fetch=True)
                updates = await self._admit_mgf_updates(model, updates, timeout=timeout)
        request = {"action": "prepare", "model": model, "updates": updates}
        if p.mgf_percentile:
            probes = [update["body"]["mgf_probe"] for update in updates]
            bound = previous["mgf_state"]["bound"]
            if p.mgf_artifact_bound:
                from .mgf_selection import artifact_selection_bound
                norm = await self._cohort_mask_norm(model, probes, timeout=timeout)
                request["mgf_cohort_norm"] = norm
                bound = artifact_selection_bound(p, registry, previous["mgf_state"], norm,
                                                  probes, digest(previous), previous["round"] + 1)
            chosen, _ = select_probes(p, registry, probes, digest(previous), previous["round"] + 1,
                                      bound)
            request["mgf_candidates"] = probes
            request["updates"] = [update for update in updates if update["sender"] in chosen]
        if p.hotstuff:
            await self._peer_hotstuff_certificate(request, timeout=timeout)
            return await self.finish_pending_roster(timeout=timeout)
        local_vote = await asyncio.to_thread(process_local_request, self.node_config, request)
        body = verify(local_vote, registry, sender=self.transport.identity.name)

        async def prepare(name: str) -> dict | None:
            try:
                return await self.transport.request(name, "roster", request, timeout=timeout)
            except ProtocolError:
                return None

        replies = await asyncio.gather(*(prepare(name) for name in p.aggregators
                                         if name != self.transport.identity.name))
        certificate(body, [local_vote, *(v for v in replies if v is not None)], p, registry)
        return await self.finish_pending_roster(timeout=timeout)

    async def _cohort_mask_norm(self, model, probes, *, timeout):
        p, registry = self.transport.p, self.transport.registry
        request = {"action": "mgf_cohort_vote", "model": model, "mgf_candidates": probes}
        local = await asyncio.to_thread(process_local_request, self.node_config, request)
        context = verify(local, registry, sender=self.transport.identity.name)
        approved = await self._peer_certificate(context, local, "mgf-cohort", request, timeout=timeout)
        request = {**request, "action": "mgf_cohort_share", "cohort_certificate": approved}

        async def ask(name):
            try:
                if name == self.transport.identity.name:
                    return await asyncio.to_thread(process_local_request, self.node_config, request)
                return await self.transport.request(name, "mgf-cohort", request, timeout=timeout)
            except ProtocolError:
                return None

        shares = [share for share in await asyncio.gather(*(ask(name) for name in p.aggregators))
                  if share is not None]
        request = {**request, "action": "mgf_cohort_norm", "cohort_shares": shares}
        local = await asyncio.to_thread(process_local_request, self.node_config, request)
        norm = verify(local, registry, sender=self.transport.identity.name)
        return await self._peer_certificate(norm, local, "mgf-cohort", request, timeout=timeout)

    async def _admit_mgf_updates(self, model: dict, updates: list[dict],
                                 *, timeout: float) -> list[dict]:
        """Keep updates whose encrypted shares pass an aggregator quorum."""
        p, registry = self.transport.p, self.transport.registry
        if not p.mgf_enabled:
            raise ProtocolError("peer MGF admission is not enabled")
        previous = check_finalized_model(model, p, registry)
        accepted = []
        for update in updates:
            request = {"action": "mgf_admit", "model": model, "update": update}
            expected = p.claim("mgf-admit", previous["round"] + 1,
                               parent=digest(previous), update=digest(update))
            try:
                local = await asyncio.to_thread(process_local_request, self.node_config, request)
            except ProtocolError:
                local = None
            try:
                await self._peer_certificate(expected, local, "mgf-admit", request,
                                             timeout=timeout)
            except ProtocolError:
                continue
            accepted.append(update)
        if len(accepted) < 2:
            raise ProtocolError("MGF peer admission retained fewer than two client updates")
        return accepted

    async def _peer_hotstuff_certificate(self, command: dict, *, timeout: float) -> dict:
        """Drive the same HotStuff application slot through authenticated peers."""
        from .hotstuff import (candidate_claim, check_new_view, check_recovery, check_status,
                               run_round, slot_for,
                               timeout_claim, vote_claim)
        p, registry = self.transport.p, self.transport.registry
        candidate = await asyncio.to_thread(process_local_request, self.node_config,
                                            {"action": "hotstuff_candidate", "command": command})
        candidate_body = verify(candidate, registry, sender=self.transport.identity.name)
        value = candidate_body.get("value") if isinstance(candidate_body, dict) else None
        if candidate_body != candidate_claim(p, value):
            raise ProtocolError("local HotStuff candidate is not independently validated")
        slot = slot_for(value)

        def valid_reply(name, request, reply):
            body = verify(reply, registry, sender=name)
            if not isinstance(body, dict):
                raise ProtocolError("invalid peer HotStuff reply")
            op = request["op"]
            if op == "status":
                check_status(p, registry, slot, reply)
            elif op == "recover":
                check_recovery(p, registry, slot, reply)
            elif op == "new_view":
                check_new_view(p, registry, slot, request["view"], reply)
            elif op in ("prepare", "precommit", "commit"):
                proposed = verify(request["proposal"], registry)
                expected = vote_claim(p, slot, op, proposed["view"], digest(proposed["value"]))
                if body != expected:
                    raise ProtocolError("peer HotStuff vote differs from proposal")
            elif op == "timeout":
                if body != timeout_claim(p, slot, request["view"]):
                    raise ProtocolError("peer HotStuff timeout differs from view")
            elif op == "decide":
                if body != request["value"]:
                    raise ProtocolError("peer HotStuff decision differs from value")
            elif op == "propose":
                if body.get("kind") != "hotstuff-proposal" or body.get("view") != request["view"]:
                    raise ProtocolError("peer HotStuff proposal differs from view")
            else:
                raise ProtocolError("unknown peer HotStuff operation")
            return reply

        async def call(names, request):
            # ``drain`` is a local transport policy, not part of the signed
            # HotStuff operation sent to replicas.
            wire_request = {key: item for key, item in request.items() if key != "drain"}

            async def one(name):
                try:
                    if name == self.transport.identity.name:
                        reply = await asyncio.to_thread(process_local_request, self.node_config, wire_request)
                    else:
                        reply = await self.transport.request(name, "hotstuff", wire_request, timeout=timeout)
                    return valid_reply(name, wire_request, reply)
                except (ProtocolError, KeyError, TypeError):
                    return None

            tasks = {asyncio.create_task(one(name)) for name in names}
            # Usually a status quorum is enough. If an old-view timeout QC
            # fails, the driver explicitly drains all statuses to find a
            # slower replica carrying the certified higher-view QC.
            collect_all = request["op"] == "status" and request.get("drain") is True
            target = min(len(names), p.quorum)
            replies = []
            try:
                while tasks and (collect_all or len(replies) < target):
                    done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    replies.extend(reply for task in done if (reply := task.result()) is not None)
                    if not collect_all and len(replies) + len(tasks) < target:
                        break
                return replies
            finally:
                for task in tasks:
                    task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

        return await run_round(p, registry, value, command, call)

    def _store_decision_proof(self, model: dict, decision: dict) -> None:
        p, registry = self.transport.p, self.transport.registry
        body = check_finalized_model(model, p, registry)
        expected = p.claim("decided", body["round"], model=digest(body))
        if not isinstance(decision, dict) or decision.get("body") != expected:
            raise ProtocolError("wrong peer decision certificate")
        certificate(expected, decision.get("votes", []), p, registry)
        path, lock_path = self._proof_paths()
        with lock_path.open("a+b") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            state = json.loads(path.read_text()) if path.exists() else {"task": p.task, "certificates": {}}
            if state.get("task") != p.task or not isinstance(state.get("certificates"), dict):
                raise ProtocolError("invalid peer decision store")
            key = str(body["round"])
            existing = state["certificates"].get(key)
            if existing is not None:
                if (not isinstance(existing, dict) or not isinstance(existing.get("model"), dict)
                        or digest(check_finalized_model(existing["model"], p, registry)) != digest(body)
                        or not isinstance(existing.get("decision"), dict)
                        or existing["decision"].get("body") != expected):
                    raise ProtocolError("conflicting peer decision proof")
                certificate(expected, existing["decision"].get("votes", []), p, registry)
                return
            state["certificates"][key] = {"model": model, "decision": decision}
            save_state(path, state)

    async def _install_decision_proof(self, transcript: dict) -> dict:
        model, decision = transcript["model"], transcript["decision"]
        p, registry = self.transport.p, self.transport.registry
        body = check_finalized_model(model, p, registry)
        expected = p.claim("decided", body["round"], model=digest(body))
        if not isinstance(decision, dict) or decision.get("body") != expected:
            raise ProtocolError("wrong peer decision certificate")
        certificate(expected, decision.get("votes", []), p, registry)
        vote = await asyncio.to_thread(process_local_request, self.node_config,
                                       {"action": "decide", "model": model})
        if vote.get("body") != expected:
            raise ProtocolError("local decision differs from peer proof")
        await asyncio.to_thread(self._store_decision_proof, model, decision)
        return vote

    async def broadcast_decision(self, model: dict, *, timeout: float = 10.0) -> dict:
        """Finish a committed model with an aggregator decision quorum.

        An already certified model is required. This can complete a model
        decision after Flower's coordinator stops, but it cannot collect new
        client updates or start the next Flower training round.
        """
        p, registry = self.transport.p, self.transport.registry
        body = check_finalized_model(model, p, registry)
        if body["round"] < 1:
            raise ProtocolError("genesis needs no peer decision")
        expected = p.claim("decided", body["round"], model=digest(body))
        local = await asyncio.to_thread(process_local_request, self.node_config,
                                        {"action": "decide", "model": model})
        if local["body"] != expected:
            raise ProtocolError("local decision differs from committed model")

        decision = await self._peer_certificate(
            expected, local, "decision", {"action": "decide", "model": model},
            timeout=timeout)
        if decision["body"] != expected:
            raise ProtocolError("peer decision quorum differs from committed model")
        await asyncio.to_thread(self._store_decision_proof, model, decision)

        async def install(name: str) -> bool:
            try:
                await self.transport.send(name, "decision-qc",
                                          {"model": model, "decision": decision}, timeout=timeout)
                return True
            except ProtocolError:
                return False

        confirmations = 1
        tasks = {asyncio.create_task(install(name)) for name in p.aggregators
                 if name != self.transport.identity.name}
        try:
            while tasks and confirmations < p.quorum:
                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                confirmations += sum(task.result() for task in done)
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        if confirmations < p.quorum:
            raise ProtocolError("decision proof not persisted by a peer quorum")
        return decision

    async def finish_model(self, model: dict, *, timeout: float = 10.0) -> dict:
        """Complete commit and decision QCs for an already proposed model QC.

        This recovers only the tail of an existing Flower round. It does not
        propose or aggregate a model, nor start a new training round.
        """
        p, registry = self.transport.p, self.transport.registry
        finalized = copy.deepcopy(model)
        body = check_certificate(finalized, p, registry)
        if body.get("kind") != "model" or type(body.get("round")) is not int or body["round"] < 1:
            raise ProtocolError("peer completion needs a certified model proposal")
        if "commits" not in finalized:
            expected = p.claim("committed", body["round"], model=digest(body))
            local = await asyncio.to_thread(process_local_request, self.node_config,
                                            {"action": "commit", "model": finalized})
            if local.get("body") != expected:
                raise ProtocolError("local commit differs from proposed model")

            finalized["commits"] = await self._peer_certificate(
                expected, local, "qc", {"action": "commit", "model": finalized},
                timeout=timeout)
        check_finalized_model(finalized, p, registry)
        finalized["decisions"] = await self.broadcast_decision(finalized, timeout=timeout)
        return finalized

    async def finish_pending_model(self, *, timeout: float = 10.0) -> dict:
        """Recover a model QC from independently durable aggregator votes.

        Flower remains the normal coordinator. This peer fallback only works
        after a quorum of aggregators has locally finalized the same model.
        """
        p, registry = self.transport.p, self.transport.registry
        local_status = await asyncio.to_thread(process_local_request, self.node_config,
                                               {"action": "proposal_proof"})
        status = verify(local_status, registry, sender=self.transport.identity.name)
        body = status.get("candidate")
        if not isinstance(body, dict) or status.get("kind") != "proposal-proof":
            raise ProtocolError("invalid durable proposal status")
        expected = p.claim("proposal-proof", body.get("round"), candidate=body,
                           vote=status.get("vote"),
                           roster_certificate=status.get("roster_certificate"),
                           consensus=status.get("consensus"),
                           **({"hotstuff": status.get("hotstuff")} if p.hotstuff else {}))
        if status != expected:
            raise ProtocolError("proposal status is not bound to this task")
        local_vote = status["vote"]
        if verify(local_vote, registry, sender=self.transport.identity.name) != body:
            raise ProtocolError("local proposal vote differs from status")
        candidate = digest(body)

        model = await self._peer_certificate(
            body, local_vote, "proposal",
            {"action": "proposal_vote", "candidate": candidate}, timeout=timeout)
        if p.leader_views:
            model["consensus"] = status["consensus"]
            model["roster_certificate"] = status["roster_certificate"]
        if p.hotstuff:
            model["hotstuff"] = status["hotstuff"]
        check_certificate(model, p, registry)
        return await self.finish_model(model, timeout=timeout)

    async def recover_roster(self, *, timeout: float = 10.0) -> dict:
        """Recover an already independently verified roster quorum via peers."""
        p, registry = self.transport.p, self.transport.registry
        local_status = await asyncio.to_thread(process_local_request, self.node_config,
                                               {"action": "roster_proof"})
        status = verify(local_status, registry, sender=self.transport.identity.name)
        body = status.get("candidate")
        if not isinstance(body, dict) or status.get("kind") != "roster-proof":
            raise ProtocolError("invalid durable roster status")
        expected = p.claim("roster-proof", body.get("round"), candidate=body,
                           vote=status.get("vote"), consensus=status.get("consensus"),
                           **({"hotstuff": status.get("hotstuff")} if p.hotstuff else {}))
        if status != expected:
            raise ProtocolError("roster status is not bound to this task")
        local_vote = status["vote"]
        if verify(local_vote, registry, sender=self.transport.identity.name) != body:
            raise ProtocolError("local roster vote differs from status")
        candidate = digest(body)

        roster = await self._peer_certificate(
            body, local_vote, "roster",
            {"action": "roster_vote", "candidate": candidate}, timeout=timeout)
        if p.leader_views:
            roster["consensus"] = status["consensus"]
        if p.hotstuff:
            roster["hotstuff"] = status["hotstuff"]
        check_certificate(roster, p, registry)
        if p.leader_views:
            expected_commit = p.claim("roster-committed", body["round"], roster=digest(body))
            local_commit = await asyncio.to_thread(process_local_request, self.node_config,
                                                   {"action": "roster_commit", "roster": roster})

            roster["commits"] = await self._peer_certificate(
                expected_commit, local_commit, "qc",
                {"action": "roster_commit", "roster": roster}, timeout=timeout)
        check_finalized_roster(roster, p, registry)
        return roster

    async def finish_pending_roster(self, *, timeout: float = 10.0) -> dict:
        """Finish a quorum-verified roster without Flower.

        The certified roster and each local pending lock gate aggregate-share
        release. Leader-view mode uses only the current finite view chain; it
        is not a complete partially synchronous HotStuff pacemaker.
        """
        p, registry = self.transport.p, self.transport.registry
        roster = await self.recover_roster(timeout=timeout)
        local_share = await asyncio.to_thread(process_local_request, self.node_config,
                                              {"action": "share", "roster": roster})

        shares = await self._peer_aggregate_shares(roster, local_share, timeout=timeout)
        if p.leader_views:
            model = await self._leader_model_certificate(roster, shares, timeout=timeout)
            return await self.finish_model(model, timeout=timeout)
        request = {"action": "finalize", "roster": roster, "shares": shares}
        if p.hotstuff:
            model = await self._peer_hotstuff_certificate(request, timeout=timeout)
            model["roster_certificate"] = roster
            check_certificate(model, p, registry)
            return await self.finish_model(model, timeout=timeout)
        local_vote = await asyncio.to_thread(process_local_request, self.node_config, request)
        body = verify(local_vote, registry, sender=self.transport.identity.name)

        async def finalize(name: str) -> dict | None:
            try:
                return await self.transport.request(name, "proposal", request, timeout=timeout)
            except ProtocolError:
                return None

        peer_votes = await asyncio.gather(*(finalize(name) for name in p.aggregators
                                            if name != self.transport.identity.name))
        model = certificate(body, [local_vote, *(vote for vote in peer_votes if vote is not None)],
                            p, registry)
        model["roster_certificate"] = roster
        check_certificate(model, p, registry)
        return await self.finish_model(model, timeout=timeout)

    async def _leader_model_certificate(self, roster: dict, shares: list[dict],
                                        *, timeout: float) -> dict:
        """Collect a leader proposal and QC over the peer path after roster QC."""
        p, registry = self.transport.p, self.transport.registry
        body = check_finalized_roster(roster, p, registry)
        round_id, context = body["round"], digest(body)
        previous_views = []

        async def call(name: str, kind: str, request: dict) -> dict | None:
            try:
                if name == self.transport.identity.name:
                    return await asyncio.to_thread(process_local_request, self.node_config, request)
                return await self.transport.request(name, kind, request, timeout=timeout)
            except ProtocolError:
                return None

        for view in range(len(p.aggregators)):
            view_qc = None
            if view:
                expected = p.claim("view-change", round_id, phase="model",
                                   view=view, context=context)
                request = {"action": "view_vote", "phase": "model", "round": round_id,
                           "view": view, "context": context, "roster": roster,
                           "previous_views": previous_views}
                votes = await asyncio.gather(*(call(name, "timeout", request)
                                               for name in p.aggregators))
                try:
                    view_qc = certificate(expected, [vote for vote in votes if vote is not None],
                                          p, registry)
                except ProtocolError:
                    break
                previous_views.append(view_qc)
            evidence = {"view": view, "view_qc": view_qc,
                        "previous_views": previous_views[:-1] if view else []}
            request = {"action": "finalize", "roster": roster, "shares": shares,
                       "consensus": evidence}
            leader = p.leader(view)
            proposal = await call(leader, "proposal", request)
            if proposal is None:
                continue
            try:
                candidate = verify(proposal, registry, sender=leader)
                if (candidate.get("kind") != "model" or candidate.get("round") != round_id
                        or candidate.get("roster") != context):
                    continue
            except ProtocolError:
                continue
            request["consensus"] = {**evidence, "proposal": proposal}
            votes = await asyncio.gather(*(call(name, "proposal", request)
                                           for name in p.aggregators))
            try:
                model = certificate(candidate, [vote for vote in votes if vote is not None],
                                    p, registry)
                model["consensus"] = request["consensus"]
                model["roster_certificate"] = roster
                check_certificate(model, p, registry)
                return model
            except ProtocolError:
                continue
        raise ProtocolError("peer model leader views exhausted without quorum")

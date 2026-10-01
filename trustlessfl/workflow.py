"""AION coordinator using the Flower Message/Grid APIs, not FedAvg aggregation."""

import asyncio
import base64
import copy
import hashlib
import json
import math

from flwr.app import Message
from flwr.serverapp import Grid

from .client_app import payload, records
from .crypto import ProtocolError, canonical, digest, verify
from .flower_chunks import CHUNK_BYTES, PAYLOAD_LIMIT, validate_blob
from .mgf_selection import admission_bound, artifact_selection_bound, check_update_probe, select_probes
from .protocol import (Parameters, certificate, check_certificate, check_finalized_model,
                       check_finalized_roster)


class AionWorkflow:
    def __init__(self, p: Parameters, registry: dict, *, timeout: float = 30,
                 quorum_attempts: int = 3, participation_schedule: dict | None = None,
                 staging_threshold_bytes: int = 12 * 1024 * 1024):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ProtocolError("timeout must be positive and finite")
        if type(quorum_attempts) is not int or quorum_attempts < 1:
            raise ProtocolError("quorum_attempts must be a positive integer")
        if type(staging_threshold_bytes) is not int or staging_threshold_bytes < 1:
            raise ProtocolError("staging threshold must be positive")
        self.p, self.registry, self.timeout = p, registry, timeout
        self.quorum_attempts = quorum_attempts
        self.staging_threshold_bytes = staging_threshold_bytes
        self.nodes: dict[str, int] = {}
        self.certified_rosters: dict[int, dict] = {}
        self.participation_schedule = None
        if participation_schedule is not None:
            if not isinstance(participation_schedule, dict) or p.ema_weight:
                raise ProtocolError("invalid participation schedule or incompatible EMA")
            normalized = {}
            for key, members in participation_schedule.items():
                valid_members = (isinstance(members, (list, tuple))
                                 and all(isinstance(name, str) for name in members))
                if valid_members:
                    valid_members = (len(members) >= 2 and len(set(members)) == len(members)
                                     and set(members) <= set(p.clients)
                                     if p.oracle_mgf or p.mgf_enabled else p.allowed_members(tuple(members)))
                if (type(key) not in (str, int) or not str(key).isdigit()
                        or int(key) < 1 or int(key) in normalized
                        or not valid_members):
                    raise ProtocolError("invalid participation schedule membership")
                normalized[int(key)] = tuple(members)
            self.participation_schedule = normalized

    def _send(self, grid: Grid, node_ids: list[int], request: dict) -> list[tuple[int, dict]]:
        raw = canonical(request)
        uploaded = None
        if len(raw) > PAYLOAD_LIMIT:
            tag, size = hashlib.sha256(raw).hexdigest(), len(raw)
            validate_blob(tag, size)
            uploaded = (tag, size)
            for offset in range(0, size, CHUNK_BYTES):
                chunk = raw[offset:offset + CHUNK_BYTES]
                votes = self._send(grid, node_ids, {"action": "wire_write", "digest": tag,
                                  "size": size, "offset": offset,
                                  "data": base64.b64encode(chunk).decode("ascii")})
                expected = self.p.claim("wire-stored", 0, digest=tag, size=size,
                                        offset=offset, length=len(chunk))
                node_ids = [node for node, vote in votes if vote["body"] == expected]
                if not node_ids:
                    return []
            request = {"action": "wire_execute", "digest": tag, "size": size,
                       **({"runtime-case": request["runtime-case"]} if "runtime-case" in request else {})}
        messages = [Message(records(request), dst_node_id=n, message_type="query.aion",
                            group_id=self.p.task, ttl=self.timeout) for n in node_ids]
        result = []
        # Drain this request before starting chunk reads on the same Grid.
        for reply in list(grid.send_and_receive(messages, timeout=self.timeout)):
            if not reply.has_error() and reply.metadata.src_node_id in node_ids:
                try:
                    envelope = payload(reply)
                    body = verify(envelope, self.registry)
                    if isinstance(body, dict) and body.get("kind") == "wire-result":
                        envelope = self._read_wire_result(grid, reply.metadata.src_node_id, envelope)
                    result.append((reply.metadata.src_node_id, envelope))
                except (ProtocolError, KeyError, TypeError, ValueError):
                    continue
        if uploaded is not None:
            self._send(grid, [node for node, _ in result], {"action": "wire_release",
                       "direction": "in", "digest": uploaded[0], "size": uploaded[1]})
        return result

    def _read_wire_result(self, grid, node, descriptor):
        body = descriptor["body"]
        tag, size = body.get("digest"), body.get("size")
        validate_blob(tag, size)
        if body != self.p.claim("wire-result", 0, digest=tag, size=size):
            raise ProtocolError("Flower response descriptor has wrong context")
        data = bytearray()
        for offset in range(0, size, CHUNK_BYTES):
            replies = self._send(grid, [node], {"action": "wire_read", "digest": tag,
                                 "size": size, "offset": offset})
            if len(replies) != 1 or replies[0][1]["sender"] != descriptor["sender"]:
                raise ProtocolError("missing Flower response chunk")
            chunk_body = replies[0][1]["body"]
            encoded = chunk_body.get("data")
            width = min(CHUNK_BYTES, size - offset)
            if (not isinstance(encoded, str) or len(encoded) != 4 * ((width + 2) // 3)
                    or chunk_body != self.p.claim("wire-chunk", 0, digest=tag, size=size,
                                                 offset=offset, data=encoded)):
                raise ProtocolError("invalid Flower response chunk context")
            chunk = base64.b64decode(encoded, validate=True)
            if len(chunk) != width:
                raise ProtocolError("invalid Flower response chunk length")
            data.extend(chunk)
        if hashlib.sha256(data).hexdigest() != tag:
            raise ProtocolError("Flower response digest mismatch")
        envelope = json.loads(data)
        verify(envelope, self.registry, sender=descriptor["sender"])
        self._send(grid, [node], {"action": "wire_release", "direction": "out",
                   "digest": tag, "size": size})
        return envelope

    def call(self, grid: Grid, names: tuple[str, ...], action: str, **kwargs) -> list[dict]:
        replies = self._send(grid, [self.nodes[n] for n in names if n in self.nodes],
                             {"action": action, **kwargs})
        unique = {}
        for node, envelope in replies:
            name = envelope["sender"]
            if name in names and self.nodes.get(name) == node:
                unique[name] = envelope
        return [unique[n] for n in names if n in unique]

    def discover(self, grid: Grid) -> None:
        replies = self._send(grid, list(grid.get_node_ids()), {"action": "hello"})
        for node, envelope in replies:
            name = envelope["sender"]
            if verify(envelope, self.registry) != self.p.claim("hello", 0):
                continue
            if name in self.nodes and self.nodes[name] != node:
                raise ProtocolError("duplicate provisioned identity")
            self.nodes[name] = node
        if self.p.mgf_enabled or self.p.oracle_mgf:
            if len(set(self.p.clients) & self.nodes.keys()) < 2:
                raise ProtocolError("dynamic selection needs at least two available clients")
        elif not any(set(group).issubset(self.nodes) for group in self.p.groups):
            raise ProtocolError("no complete privacy group available")
        if len(set(self.p.aggregators) & self.nodes.keys()) < self.p.quorum:
            raise ProtocolError("insufficient available aggregators")

    def agree(self, votes: list[dict]) -> dict:
        for vote in votes:
            try:
                return certificate(vote["body"], votes, self.p, self.registry)
            except ProtocolError:
                continue
        raise ProtocolError("no aggregator quorum agreed; round aborted")

    def quorum_call(self, grid: Grid, action: str, **kwargs) -> dict:
        """Retry idempotent signed votes after transient loss, then fail closed."""
        if self.p.hotstuff and action in ("prepare", "finalize"):
            from .hotstuff import candidate_claim, make_qc, run_round
            command = {"action": action, **kwargs}
            candidates = self.call(grid, self.p.aggregators, "hotstuff_candidate", command=command)
            value = None
            for envelope in candidates:
                try:
                    body = verify(envelope, self.registry)
                    if not isinstance(body, dict):
                        continue
                    proposed = body.get("value")
                    if body == candidate_claim(self.p, proposed):
                        make_qc(self.p, self.registry, body, candidates)
                        value = proposed
                        break
                except (ProtocolError, KeyError, TypeError):
                    continue
            if value is None:
                raise ProtocolError("HotStuff application candidate quorum unavailable")

            async def call(names, request):
                return self.call(grid, names, request["action"],
                                 **{k: v for k, v in request.items() if k != "action"})

            return asyncio.run(run_round(self.p, self.registry, value, command, call))
        if self.p.leader_views and action in ("prepare", "finalize"):
            return self.leader_quorum_call(grid, action, **kwargs)
        votes = []
        for _ in range(self.quorum_attempts):
            votes.extend(self.call(grid, self.p.aggregators, action, **kwargs))
            try:
                return self.agree(votes)
            except ProtocolError:
                continue
        raise ProtocolError(f"{action} quorum unavailable after retries")

    def _prepare_payload(self, grid: Grid, current: dict, updates: list[dict], late,
                         mgf_candidates=None, mgf_cohort_norm=None) -> dict:
        """Stage large signed updates once per aggregator before roster voting."""
        request = {"model": current, "updates": updates, "late": late}
        if mgf_candidates is not None:
            request["mgf_candidates"] = mgf_candidates
        if mgf_cohort_norm is not None:
            request["mgf_cohort_norm"] = mgf_cohort_norm
        if len(canonical({"action": "prepare", **request})) <= self.staging_threshold_bytes:
            return request
        common = set(self.p.aggregators)
        references = []
        for envelope in updates:
            sender = envelope["sender"]
            round_id = current["body"]["round"] + 1
            expected = self.p.claim("update-staged", round_id,
                                    client=sender, update=digest(envelope))
            votes = self.call(grid, self.p.aggregators, "stage_update", update=envelope)
            acknowledged = set()
            for vote in votes:
                try:
                    if verify(vote, self.registry) == expected:
                        acknowledged.add(vote["sender"])
                except ProtocolError:
                    continue
            common.intersection_update(acknowledged)
            if len(common) < self.p.quorum:
                raise ProtocolError("signed update staging lost an aggregator quorum")
            references.append({"client": sender, "digest": digest(envelope)})
        return {"model": current, "staged": references, "late": late,
                **({"mgf_cohort_norm": mgf_cohort_norm} if mgf_cohort_norm is not None else {}),
                **({"mgf_candidates": mgf_candidates} if mgf_candidates is not None else {})}

    def cohort_mask_norm(self, grid, current, probes):
        common = {"model": current, "mgf_candidates": probes}
        votes = self.call(grid, self.p.aggregators, "mgf_cohort_vote", **common)
        if not votes:
            raise ProtocolError("MGF cohort approval unavailable")
        approved = certificate(votes[0]["body"], votes, self.p, self.registry)
        common["cohort_certificate"] = approved
        shares = self.call(grid, self.p.aggregators, "mgf_cohort_share", **common)
        norms = self.call(grid, self.p.aggregators, "mgf_cohort_norm", **common, cohort_shares=shares)
        if not norms:
            raise ProtocolError("MGF cohort mask norm unavailable")
        return certificate(norms[0]["body"], norms, self.p, self.registry)

    def leader_quorum_call(self, grid: Grid, action: str, **kwargs) -> dict:
        """Rotate a stalled proposal leader using a signed view-change quorum."""
        if action == "prepare":
            previous = check_finalized_model(kwargs["model"], self.p, self.registry)
            phase, round_id, context = "roster", previous["round"] + 1, digest(previous)
        elif action == "finalize":
            roster = check_finalized_roster(kwargs["roster"], self.p, self.registry)
            phase, round_id, context = "model", roster["round"], digest(roster)
        else:
            raise ProtocolError("unsupported leader phase")
        previous_views = []
        for view in range(len(self.p.aggregators)):
            view_qc = None
            if view:
                expected = self.p.claim("view-change", round_id, phase=phase,
                                        view=view, context=context)
                view_qc = self.quorum_call(grid, "view_vote", phase=phase, round=round_id,
                                           view=view, context=context,
                                           previous_views=previous_views)
                if view_qc["body"] != expected:
                    raise ProtocolError("incorrect view-change quorum")
                previous_views.append(view_qc)
            evidence = {"view": view, "view_qc": view_qc,
                        "previous_views": previous_views[:-1] if view else []}
            leader = self.p.leader(view)
            proposals = []
            for _ in range(self.quorum_attempts):
                proposals = self.call(grid, (leader,), action, **kwargs, consensus=evidence)
                if proposals:
                    break
            if not proposals:
                continue
            proposal = proposals[0]
            try:
                body = verify(proposal, self.registry, sender=leader)
                if (body.get("kind") != phase or body.get("round") != round_id
                        or body.get("parent" if phase == "roster" else "roster") != context):
                    continue
            except ProtocolError:
                continue
            evidence = {**evidence, "proposal": proposal}
            votes = []
            for _ in range(self.quorum_attempts):
                votes.extend(self.call(grid, self.p.aggregators, action,
                                       **kwargs, consensus=evidence))
                try:
                    result = certificate(body, votes, self.p, self.registry)
                    result["consensus"] = evidence
                    check_certificate(result, self.p, self.registry)
                    return result
                except ProtocolError:
                    continue
        raise ProtocolError(f"{action} leader views exhausted without quorum")

    def _restore_checkpoint(self, checkpoint: dict, rounds: int) -> tuple[list[dict], dict]:
        if not isinstance(checkpoint, dict) or checkpoint.get("task") != self.p.task:
            raise ProtocolError("checkpoint belongs to another task")
        history = checkpoint.get("history")
        omitted = checkpoint.get("omitted")
        if (not isinstance(history, list) or not 1 <= len(history) <= rounds + 1
                or not isinstance(omitted, dict) or any(c not in self.p.clients for c in omitted)):
            raise ProtocolError("invalid workflow checkpoint")
        previous = None
        for index, cert in enumerate(history):
            body = check_finalized_model(cert, self.p, self.registry)
            if body["round"] != index or body.get("parent") != (digest(previous) if previous else ""):
                raise ProtocolError("checkpoint model chain is not contiguous")
            if (previous is not None and "ancestry" in previous
                    and body.get("ancestry") != [*previous["ancestry"], digest(previous)]):
                raise ProtocolError("checkpoint model ancestry is not contiguous")
            if index:
                expected = self.p.claim("decided", index, model=digest(body))
                decision = cert.get("decisions")
                if not isinstance(decision, dict) or decision.get("body") != expected:
                    raise ProtocolError("checkpoint lacks model decision quorum")
                certificate(expected, decision.get("votes", []), self.p, self.registry)
            previous = body
        last_round = len(history) - 1
        if (not self.p.ema_weight and omitted) or (last_round == 0 and omitted):
            raise ProtocolError("unexpected pending EMA checkpoint entries")
        if any(set(group).intersection(omitted) and not set(group).issubset(omitted)
               for group in self.p.groups):
            raise ProtocolError("checkpoint splits a pending privacy group")
        for client, envelope in omitted.items():
            if envelope is None:
                continue
            if not isinstance(envelope, dict) or envelope.get("sender") != client:
                raise ProtocolError("invalid omitted client update")
            body = verify(envelope, self.registry, sender=client)
            expected = self.p.claim("update", last_round)
            if (any(body.get(k) != v for k, v in expected.items())
                    or body.get("parent") != digest(check_finalized_model(
                        history[-2], self.p, self.registry))):
                raise ProtocolError("omitted update belongs to another round")
            vector = body.get("vector")
            modulus = self.p.codec.output_modulus
            if (not isinstance(vector, list) or len(vector) != self.p.dimension
                    or any(type(value) is not int or not 0 <= value < modulus
                           for value in vector)):
                raise ProtocolError("invalid omitted masked vector")
        return history, omitted

    def _recover_peer_history(self, grid: Grid, history: list[dict], rounds: int) -> list[dict]:
        """Recover fixed-cohort decisions independently persisted by peers."""
        if self.p.ema_weight:
            return history  # Omitted-group state is not reconstructible from decision proofs.
        reports: dict[str, dict] = {}
        for _ in range(self.quorum_attempts):
            for report in self.call(grid, self.p.aggregators, "recover"):
                reports[report["sender"]] = report
            if len(reports) == len(self.p.aggregators):
                break
        if len(reports) < self.p.quorum:
            raise ProtocolError("insufficient peer recovery reports")

        best = history
        last_rounds = []
        valid_reports = 0
        expected_report = self.p.claim("recovery", 0)
        for report in reports.values():
            try:
                body = verify(report, self.registry)
                if any(body.get(key) != value for key, value in expected_report.items()):
                    continue
                last_round = body.get("last_round")
                proofs = body.get("proofs")
                if (type(last_round) is not int or last_round < 0
                        or not isinstance(proofs, list) or len(proofs) > rounds):
                    continue
                candidate = [history[0]]
                previous = history[0]["body"]
                for index, proof in enumerate(proofs, start=1):
                    if not isinstance(proof, dict) or not isinstance(proof.get("model"), dict):
                        raise ProtocolError("invalid peer decision proof")
                    model = copy.deepcopy(proof["model"])
                    model["decisions"] = proof["decision"]
                    current = check_finalized_model(model, self.p, self.registry)
                    expected_decision = self.p.claim("decided", index, model=digest(current))
                    decision = model["decisions"]
                    if (current["round"] != index or current.get("parent") != digest(previous)
                            or not isinstance(decision, dict) or decision.get("body") != expected_decision):
                        raise ProtocolError("peer decision chain is not contiguous")
                    certificate(expected_decision, decision.get("votes", []), self.p, self.registry)
                    candidate.append(model)
                    previous = current
                if last_round < len(proofs):
                    continue
            except (ProtocolError, KeyError, TypeError, ValueError):
                continue
            for index in range(min(len(history), len(candidate))):
                if history[index]["body"] != candidate[index]["body"]:
                    raise ProtocolError("peer recovery conflicts with server checkpoint")
            for index in range(min(len(best), len(candidate))):
                if best[index]["body"] != candidate[index]["body"]:
                    raise ProtocolError("conflicting certified peer histories")
            if len(candidate) > len(best):
                best = candidate
            last_rounds.append(last_round)
            valid_reports += 1
        if valid_reports < self.p.quorum:
            raise ProtocolError("insufficient valid peer recovery reports")
        if sum(value >= len(best) for value in last_rounds) >= self.p.faults + 1:
            raise ProtocolError("peer committed state exceeds available decision proofs")
        if len(best) > len(history):
            self._restore_checkpoint({"task": self.p.task, "history": best, "omitted": {}}, rounds)
        return best

    def run(self, grid: Grid, rounds: int, *, checkpoint: dict | None = None,
            on_checkpoint=None) -> list[dict]:
        if type(rounds) is not int or rounds < 1:
            raise ProtocolError("rounds must be a positive integer")
        self.discover(grid)
        if checkpoint is None:
            enrollments = self.call(grid, self.p.clients, "enroll")
            if len(enrollments) != len(self.p.clients):
                raise ProtocolError("incomplete enrollment")
            current = self.quorum_call(grid, "initialize", enrollments=enrollments)
            history = [current]
            omitted: dict[str, dict | None] = {}
        else:
            history, omitted = self._restore_checkpoint(checkpoint, rounds)
        history = self._recover_peer_history(grid, history, rounds)
        current = history[-1]
        if on_checkpoint is not None:
            on_checkpoint({"task": self.p.task, "history": history, "omitted": omitted})
        for round_id in range(len(history), rounds + 1):
            late = None
            if self.p.ema_weight and omitted:
                stale = history[-2]
                # `omitted` maps each client to its signed update, or None.
                missing = tuple(c for c, update in omitted.items() if update is None)
                recovery = {"model": stale}
                if self.p.privacy_groups and round_id > 2 and "ancestry" not in stale["body"]:
                    recovery["history"] = history[:-1]
                recovered = self.call(grid, missing, "train", **recovery)
                candidates = {**omitted, **{u["sender"]: u for u in recovered}}
                ready = {c for group in self.p.groups if all(candidates.get(name) is not None for name in group)
                         for c in group if c in candidates}
                late_updates = [candidates[c] for c in self.p.clients if c in ready]
                if late_updates:
                    late_roster = self.quorum_call(grid, "late_prepare",
                                                   current=current, previous=stale, updates=late_updates)
                    late_shares = []
                    for _ in range(self.quorum_attempts):
                        late_shares.extend(self.call(grid, self.p.aggregators, "late_share", roster=late_roster))
                        try:
                            late = self.quorum_call(grid, "late_finalize",
                                                    roster=late_roster, shares=late_shares)
                            break
                        except ProtocolError:
                            continue
                    if late is None:
                        raise ProtocolError("late aggregate quorum unavailable after retries")
            training_request = {"model": current}
            if self.p.privacy_groups and round_id > 1 and "ancestry" not in current["body"]:
                training_request["history"] = history
            selected = self.p.clients
            if self.participation_schedule is not None:
                selected = self.participation_schedule.get(round_id)
                if selected is None:
                    raise ProtocolError("missing scheduled client cohort for round")
            received = self.call(grid, selected, "train", **training_request)
            by_client = {u["sender"]: u for u in received}
            mgf_candidates = None
            mgf_cohort_norm = None
            if self.p.mgf_enabled:
                state = current["body"]["mgf_state"]
                updates = []
                for client in self.p.clients:
                    envelope = by_client.get(client)
                    if envelope is None:
                        continue
                    body = verify(envelope, self.registry, sender=client)
                    if not isinstance(body, dict):
                        continue
                    material = body.get("mgf")
                    if (body.get("parent") != digest(current["body"])
                            or not isinstance(material, dict)
                            or material.get("alpha") != state["alpha"]):
                        continue
                    try:
                        if self.p.mgf_percentile:
                            check_update_probe(self.p, self.registry, body)
                        if self.p.mgf_codec.accepts(body.get("mgf_vector" if self.p.mgf_projection else "vector"), admission_bound(self.p, state)):
                            updates.append(envelope)
                    except ProtocolError:
                        continue
                if len(updates) < 2:
                    raise ProtocolError("MGF retained fewer than two client updates")
                if self.p.mgf_percentile:
                    mgf_candidates = [update["body"]["mgf_probe"] for update in updates]
                    bound = state["bound"]
                    if self.p.mgf_artifact_bound:
                        mgf_cohort_norm = self.cohort_mask_norm(grid, current, mgf_candidates)
                        bound = artifact_selection_bound(self.p, self.registry, state,
                            mgf_cohort_norm, mgf_candidates, digest(current["body"]), round_id)
                    chosen, _ = select_probes(self.p, self.registry, mgf_candidates,
                        digest(current["body"]), round_id, bound)
                    updates = [update for update in updates if update["sender"] in chosen]
                admitted = []
                for envelope in updates:
                    claim = self.p.claim("mgf-admit", round_id,
                                         parent=digest(current["body"]),
                                         update=digest(envelope))
                    votes = self.call(grid, self.p.aggregators, "mgf_admit",
                                      model=current, update=envelope)
                    try:
                        certificate(claim, votes, self.p, self.registry)
                    except ProtocolError:
                        continue
                    admitted.append(envelope)
                updates = admitted
                if self.p.mgf_percentile and len(updates) != len(chosen):
                    raise ProtocolError("percentile-selected MGF update failed share admission")
                if len(updates) < 2:
                    raise ProtocolError("MGF admission retained fewer than two client updates")
                omitted = {}
            elif self.p.oracle_mgf:
                updates = [by_client[c] for c in selected if c in by_client]
                if len(updates) < 2:
                    raise ProtocolError("oracle MGF needs at least two client updates")
                updates = self.oracle_filter(updates, current, round_id)
                omitted = {}
            else:
                active = {name for group in self.p.groups if all(c in by_client for c in group)
                          for name in group}
                if not active:
                    raise ProtocolError("no complete privacy group responded (dropout); round aborted")
                updates = [by_client[c] for c in self.p.clients if c in active]
                omitted = {c: by_client.get(c) for group in self.p.groups if not all(name in active for name in group)
                           for c in group} if self.p.ema_weight else {}
            roster = self.quorum_call(grid, "prepare",
                                      **self._prepare_payload(grid, current, updates, late, mgf_candidates, mgf_cohort_norm))
            if mgf_candidates is not None:
                roster["mgf_candidates"] = mgf_candidates
            if self.p.leader_views:
                roster_body = check_certificate(roster, self.p, self.registry)
                expected_roster_commit = self.p.claim(
                    "roster-committed", round_id, roster=digest(roster_body))
                roster_commits = []
                for _ in range(self.quorum_attempts):
                    roster_commits.extend(self.call(grid, self.p.aggregators,
                                                    "roster_commit", roster=roster))
                    try:
                        roster["commits"] = certificate(
                            expected_roster_commit, roster_commits, self.p, self.registry)
                        break
                    except ProtocolError:
                        continue
                if "commits" not in roster:
                    raise ProtocolError("roster commit quorum unavailable after retries")
            certified_roster = check_finalized_roster(roster, self.p, self.registry)
            if certified_roster["round"] != round_id:
                raise ProtocolError("certified roster has the wrong round")
            self.certified_rosters[round_id] = roster
            shares = []
            result = None
            for _ in range(self.quorum_attempts):
                shares.extend(self.call(grid, self.p.aggregators, "share", roster=roster))
                try:
                    result = self.quorum_call(grid, "finalize", roster=roster, shares=shares)
                    break
                except ProtocolError:
                    continue
            if result is None:
                raise ProtocolError("aggregate quorum unavailable after retries")
            if self.p.leader_views:
                result["roster_certificate"] = roster
            body = check_certificate(result, self.p, self.registry)
            if body["kind"] != "model" or body["round"] != round_id:
                raise ProtocolError("unexpected model certificate")
            expected = self.p.claim("committed", round_id, model=digest(body))
            commits = []
            for _ in range(self.quorum_attempts):
                commits.extend(self.call(grid, self.p.aggregators, "commit", model=result))
                try:
                    result["commits"] = certificate(expected, commits, self.p, self.registry)
                    break
                except ProtocolError:
                    continue
            if "commits" not in result:
                raise ProtocolError("commit quorum unavailable after retries")
            check_finalized_model(result, self.p, self.registry)
            expected_decision = self.p.claim("decided", round_id, model=digest(body))
            decision = self.quorum_call(grid, "decide", model=result)
            if decision["body"] != expected_decision:
                raise ProtocolError("incorrect model decision quorum")
            result["decisions"] = decision
            if self.p.oracle_mgf:
                self.oracle_observe(current, result, round_id)
            current = result
            history.append(current)
            if on_checkpoint is not None:
                on_checkpoint({"task": self.p.task, "history": history, "omitted": omitted})
        return history

    def oracle_filter(self, updates: list[dict], current: dict, round_id: int) -> list[dict]:
        raise ProtocolError("plaintext oracle MGF requires an explicit research workflow")

    def oracle_observe(self, previous: dict, result: dict, round_id: int) -> None:
        raise ProtocolError("plaintext oracle MGF requires an explicit research workflow")

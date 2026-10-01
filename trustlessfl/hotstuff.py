"""Single-slot Basic HotStuff voting core for AION roster/model decisions.

Prepare, pre-commit, and commit are separate voting phases. A slot is bound
to an AION round and its already-certified parent. Re-proposing the same
value in later views is the single-slot equivalent of extending its branch.
The caller must durably persist state before releasing a returned signature.

This module does not supply a distributed pacemaker. The bounded driver is
useful through Flower or an authenticated peer transport, but cannot alone
establish partial-synchrony liveness. QCs currently carry individual Ed25519
signatures rather than a constant-size threshold signature.
"""

from __future__ import annotations

import copy
import math
import time
import asyncio
from pathlib import Path

from .crypto import ProtocolError, digest, verify


def _boot_epoch() -> str | None:
    """Identify the monotonic-clock epoch across worker process restarts.

    Linux exposes one UUID per boot. If it is unavailable, no persisted
    monotonic timestamp can safely be interpreted after a process restart.
    """
    try:
        epoch = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return None
    return epoch if epoch else None


_CLOCK_EPOCH = _boot_epoch()


def slot_for(value: dict) -> dict:
    if not isinstance(value, dict):
        raise ProtocolError("invalid HotStuff value")
    phase, round_id = value.get("kind"), value.get("round")
    context = value.get("parent" if phase == "roster" else "roster")
    slot = {"phase": phase, "round": round_id, "context": context}
    check_slot(slot)
    return slot


def check_slot(slot: dict) -> None:
    if (not isinstance(slot, dict) or set(slot) != {"phase", "round", "context"}
            or slot["phase"] not in ("roster", "model")
            or type(slot["round"]) is not int or slot["round"] < 1
            or not isinstance(slot["context"], str) or len(slot["context"]) != 64
            or any(c not in "0123456789abcdef" for c in slot["context"])):
        raise ProtocolError("invalid HotStuff slot")


def claim(p, slot: dict, kind: str, view: int, **kwargs) -> dict:
    check_slot(slot)
    if type(view) is not int or view < (0 if kind == "status" else 1):
        raise ProtocolError("invalid HotStuff view")
    return p.claim("hotstuff-" + kind, slot["round"], phase=slot["phase"],
                   context=slot["context"], view=view, **kwargs)


def vote_claim(p, slot: dict, stage: str, view: int, value_hash: str) -> dict:
    if stage not in ("prepare", "precommit", "commit"):
        raise ProtocolError("invalid HotStuff vote stage")
    return claim(p, slot, "vote", view, stage=stage, value=value_hash)


def candidate_claim(p, value: dict) -> dict:
    slot = slot_for(value)
    return p.claim("hotstuff-candidate", slot["round"], phase=slot["phase"],
                   context=slot["context"], value=value)


def make_qc(p, registry: dict, body: dict, votes: list[dict]) -> dict:
    unique = {}
    if not isinstance(votes, list):
        raise ProtocolError("invalid HotStuff votes")
    for envelope in votes:
        try:
            if verify(envelope, registry) == body and envelope["sender"] in p.aggregators:
                unique[envelope["sender"]] = envelope
        except ProtocolError:
            continue
    if len(unique) < p.quorum:
        raise ProtocolError("HotStuff quorum unavailable")
    return {"body": body, "votes": [unique[name] for name in sorted(unique)]}


def check_qc(p, registry: dict, slot: dict, qc: dict, stage: str,
             *, view: int | None = None, value_hash: str | None = None) -> dict:
    if not isinstance(qc, dict) or not isinstance(qc.get("body"), dict):
        raise ProtocolError("missing HotStuff QC")
    body = qc["body"]
    hashed = body.get("value")
    if (not isinstance(hashed, str) or len(hashed) != 64
            or any(c not in "0123456789abcdef" for c in hashed)
            or body != vote_claim(p, slot, stage, body.get("view"), hashed)
            or (view is not None and body["view"] != view)
            or (value_hash is not None and hashed != value_hash)):
        raise ProtocolError("HotStuff QC context mismatch")
    make_qc(p, registry, body, qc.get("votes"))
    return body


def check_decision(p, registry: dict, value: dict, qc: dict) -> None:
    check_qc(p, registry, slot_for(value), qc, "commit", value_hash=digest(value))


def timeout_claim(p, slot: dict, view: int) -> dict:
    return claim(p, slot, "timeout", view)


def make_timeout_qc(p, registry: dict, slot: dict, view: int,
                    votes: list[dict]) -> dict:
    return make_qc(p, registry, timeout_claim(p, slot, view), votes)


def check_timeout_qc(p, registry: dict, slot: dict, view: int, qc: dict) -> None:
    if not isinstance(qc, dict) or qc.get("body") != timeout_claim(p, slot, view):
        raise ProtocolError("HotStuff timeout QC context mismatch")
    make_qc(p, registry, qc["body"], qc.get("votes"))


def check_status(p, registry: dict, slot: dict, envelope: dict) -> dict:
    body = verify(envelope, registry)
    if not isinstance(body, dict) or envelope["sender"] not in p.aggregators:
        raise ProtocolError("invalid HotStuff status")
    view = body.get("view")
    if body != claim(p, slot, "status", view, decision=body.get("decision"),
                     entry=body.get("entry"), timeout_qc=body.get("timeout_qc")):
        raise ProtocolError("HotStuff status belongs to another slot")
    if view > 1:
        check_timeout_qc(p, registry, slot, view - 1, body["timeout_qc"])
    elif body["timeout_qc"] is not None:
        raise ProtocolError("unexpected HotStuff status timeout QC")
    if body["decision"] is not None:
        entry = body["entry"]
        if not isinstance(entry, dict) or slot_for(entry.get("value")) != slot:
            raise ProtocolError("HotStuff decision has no matching value")
        check_decision(p, registry, entry["value"], body["decision"])
    elif body["entry"] is not None:
        raise ProtocolError("uncertified HotStuff status entry")
    return body


def check_proposal(p, registry: dict, slot: dict, envelope: dict) -> dict:
    body = verify(envelope, registry)
    if not isinstance(body, dict):
        raise ProtocolError("invalid HotStuff proposal")
    view = body.get("view")
    expected = claim(p, slot, "proposal", view, value=body.get("value"),
                     command=body.get("command"), new_views=body.get("new_views"),
                     justify=body.get("justify"))
    if body != expected or envelope["sender"] != p.leader(view - 1):
        raise ProtocolError("incorrect HotStuff proposal leader or context")
    highest = highest_new_view(p, registry, slot, view, body["new_views"])
    justify = highest["high_qc"] if highest else None
    if body["justify"] != justify or (highest and body["value"] != highest["value"]):
        raise ProtocolError("HotStuff proposal ignores high QC")
    if slot_for(body["value"]) != slot or not isinstance(body["command"], dict):
        raise ProtocolError("HotStuff proposal has invalid application value")
    return body


def check_recovery(p, registry: dict, slot: dict, envelope: dict) -> dict:
    body = verify(envelope, registry)
    if not isinstance(body, dict) or envelope["sender"] not in p.aggregators:
        raise ProtocolError("invalid HotStuff recovery report")
    view = body.get("view")
    if body != claim(p, slot, "recovery", view, proposal=body.get("proposal"),
                     prepare_qc=body.get("prepare_qc")):
        raise ProtocolError("HotStuff recovery report belongs to another slot")
    proposal, prepare_qc = body["proposal"], body["prepare_qc"]
    if proposal is not None:
        proposed = check_proposal(p, registry, slot, proposal)
        if proposed["view"] != view:
            raise ProtocolError("HotStuff recovery proposal differs from current view")
    if prepare_qc is not None:
        checked = check_qc(p, registry, slot, prepare_qc, "prepare", view=view)
        if proposal is not None and checked["value"] != digest(proposed["value"]):
            raise ProtocolError("HotStuff recovery QC differs from proposal")
    return body


def check_new_view(p, registry: dict, slot: dict, view: int,
                   envelope: dict) -> dict:
    body = verify(envelope, registry)
    if not isinstance(body, dict) or envelope["sender"] not in p.aggregators:
        raise ProtocolError("invalid HotStuff new-view body")
    if body != claim(p, slot, "new-view", view, high_qc=body.get("high_qc"),
                     value=body.get("value"), command=body.get("command"),
                     timeout_qc=body.get("timeout_qc")):
        raise ProtocolError("invalid HotStuff new-view context")
    if view > 1:
        check_timeout_qc(p, registry, slot, view - 1, body["timeout_qc"])
    elif body["timeout_qc"] is not None:
        raise ProtocolError("unexpected timeout QC in initial view")
    qc = body["high_qc"]
    if qc is None:
        if body["value"] is not None or body["command"] is not None:
            raise ProtocolError("uncertified new-view value")
    else:
        checked = check_qc(p, registry, slot, qc, "prepare")
        if (checked["view"] >= view or digest(body["value"]) != checked["value"]
                or not isinstance(body["command"], dict) or slot_for(body["value"]) != slot):
            raise ProtocolError("invalid prepared value in new-view")
    return body


def highest_new_view(p, registry: dict, slot: dict, view: int, messages: list[dict]):
    """Validate distinct new-view reports and select their highest prepare QC."""
    if not isinstance(messages, list):
        raise ProtocolError("invalid HotStuff new-view set")
    unique, highest = set(), None
    for envelope in messages:
        body = check_new_view(p, registry, slot, view, envelope)
        name = envelope["sender"]
        if name in unique:
            raise ProtocolError("duplicate HotStuff new-view")
        unique.add(name)
        qc = body["high_qc"]
        if qc is None:
            continue
        checked = qc["body"]
        if highest is None or checked["view"] > highest["high_qc"]["body"]["view"]:
            highest = body
        elif (checked["view"] == highest["high_qc"]["body"]["view"]
              and checked["value"] != highest["high_qc"]["body"]["value"]):
            raise ProtocolError("conflicting same-view prepare QCs")
    if len(unique) < p.quorum:
        raise ProtocolError("HotStuff new-view quorum unavailable")
    return highest


class HotStuffSlot:
    """Durable voting rules; validate(value, command) checks AION semantics."""

    def __init__(self, identity, p, registry, slot, state, validate, *, reuse_validation=False):
        check_slot(slot)
        if identity.name not in p.aggregators or registry.get(identity.name) != identity.public():
            raise ProtocolError("HotStuff requires pinned aggregator identity")
        if _CLOCK_EPOCH is None:
            raise ProtocolError("HotStuff requires a persistent monotonic clock epoch")
        self.identity, self.p, self.registry = identity, p, registry
        self.slot, self.state, self.validate = slot, state, validate
        # Opt-in only: callers must bind immutable application inputs to slot
        # and command. Generic validators may depend on changing external data.
        self.reuse_validation = reuse_validation
        state.setdefault("view", 0)
        state.setdefault("votes", {})
        state.setdefault("values", {})
        state.setdefault("proposals", {})
        if state["view"]:
            started = state.get("view_started_at")
            if (state.get("view_clock_epoch") != _CLOCK_EPOCH
                    or type(started) not in (int, float) or not math.isfinite(started)
                    or started > time.monotonic()):
                # A reboot changes monotonic's origin, even if the new uptime
                # already exceeds the persisted timestamp. Process restarts
                # within the same boot must not reset an ongoing view timer.
                state["view_started_at"] = time.monotonic()
                state["view_clock_epoch"] = _CLOCK_EPOCH

    def _remember(self, value, command):
        value, command = copy.deepcopy(value), copy.deepcopy(command)
        if slot_for(value) != self.slot:
            raise ProtocolError("HotStuff value belongs to another slot")
        value_hash = digest(value)
        command_hash = digest(command)
        expected = self.p.claim("hotstuff-local-validation", self.slot["round"],
                                slot=digest(self.slot), value=value_hash, command=command_hash)
        entry = self.state["values"].get(value_hash)
        if (self.reuse_validation and isinstance(entry, dict)
                and entry.get("value") == value and entry.get("command") == command
                and "validation" in entry):
            if verify(entry["validation"], self.registry, sender=self.identity.name) != expected:
                raise ProtocolError("invalid local HotStuff validation proof")
            return
        self.validate(value, command)
        if self.reuse_validation and (digest(value) != value_hash or digest(command) != command_hash):
            raise ProtocolError("HotStuff validator mutated application inputs")
        value_hash = digest(value)
        self.state["values"][value_hash] = {"value": value, "command": command,
            **({"validation": self.identity.sign(expected)} if self.reuse_validation else {})}

    def _vote(self, stage, view, value_hash):
        if view != self.state["view"]:
            raise ProtocolError("HotStuff vote is not in current view")
        decision = self.state.get("decision")
        if decision is not None and decision["body"]["value"] != value_hash:
            raise ProtocolError("HotStuff value conflicts with decision")
        key = f"{stage}/{view}"
        prior = self.state["votes"].get(key)
        if prior is not None and prior != value_hash:
            raise ProtocolError("HotStuff double vote")
        self.state["votes"][key] = value_hash
        return self.identity.sign(vote_claim(self.p, self.slot, stage, view, value_hash))

    def _learn_prepare(self, qc):
        old = self.state.get("prepare_qc")
        if old is None or qc["body"]["view"] > old["body"]["view"]:
            self.state["prepare_qc"] = copy.deepcopy(qc)
        elif (qc["body"]["view"] == old["body"]["view"]
              and qc["body"]["value"] != old["body"]["value"]):
            raise ProtocolError("conflicting prepare QCs")

    def status(self):
        decision = self.state.get("decision")
        entry = self.state["values"].get(decision["body"]["value"]) if decision else None
        return self.identity.sign(claim(self.p, self.slot, "status", self.state["view"],
                                        decision=decision, entry=entry,
                                        timeout_qc=self.state.get("enter_qc")))

    def recover(self):
        view = self.state["view"]
        if view < 1:
            raise ProtocolError("HotStuff recovery requires an entered view")
        qc = self.state.get("prepare_qc")
        return self.identity.sign(claim(
            self.p, self.slot, "recovery", view,
            proposal=self.state["proposals"].get(str(view)),
            prepare_qc=qc if qc is not None and qc["body"]["view"] == view else None))

    def new_view(self, view, timeout_qc=None):
        claim(self.p, self.slot, "new-view", view)  # validate view type
        if view < self.state["view"]:
            raise ProtocolError("HotStuff view rollback")
        if view > 1:
            check_timeout_qc(self.p, self.registry, self.slot, view - 1, timeout_qc)
        elif timeout_qc is not None:
            raise ProtocolError("unexpected initial-view timeout QC")
        qc = self.state.get("prepare_qc")
        if qc is not None and qc["body"]["view"] >= view:
            raise ProtocolError("new view must follow its prepare QC")
        if view > self.state["view"]:
            self.state["view_started_at"] = time.monotonic()
            self.state["view_clock_epoch"] = _CLOCK_EPOCH
        self.state["view"] = view
        self.state["enter_qc"] = copy.deepcopy(timeout_qc)
        entry = self.state["values"][qc["body"]["value"]] if qc else None
        return self.identity.sign(claim(self.p, self.slot, "new-view", view, high_qc=qc,
                                        value=entry["value"] if entry else None,
                                        command=entry["command"] if entry else None,
                                        timeout_qc=timeout_qc))

    def timeout(self, view):
        """Sign a timeout only after this replica's own view timer expires."""
        if type(view) is not int or view != self.state["view"] or view < 1:
            raise ProtocolError("HotStuff timeout is not in current view")
        started = self.state.get("view_started_at")
        now = time.monotonic()
        if (self.state.get("view_clock_epoch") != _CLOCK_EPOCH
                or type(started) not in (int, float) or not math.isfinite(started)):
            raise ProtocolError("missing local HotStuff view timer")
        if started > now:
            started = now
            self.state["view_started_at"] = now
        delay = math.ldexp(0.5, min(view - 1, 1023))
        if now - started < delay:
            raise ProtocolError("HotStuff local view has not timed out")
        return self.identity.sign(timeout_claim(self.p, self.slot, view))

    def propose(self, view, messages, value, command):
        if self.identity.name != self.p.leader(view - 1) or view != self.state["view"]:
            raise ProtocolError("HotStuff proposal requires current leader")
        highest = highest_new_view(self.p, self.registry, self.slot, view, messages)
        if highest is not None:
            value, command = highest["value"], highest["command"]
        self._remember(value, command)
        hashed = digest(value)
        key = f"proposal/{view}"
        prior = self.state["votes"].get(key)
        if prior is not None and prior != hashed:
            raise ProtocolError("HotStuff leader equivocation")
        self.state["votes"][key] = hashed
        return self.identity.sign(claim(self.p, self.slot, "proposal", view, value=value,
                                        command=command, new_views=messages,
                                        justify=highest["high_qc"] if highest else None))

    def _proposal(self, envelope):
        return check_proposal(self.p, self.registry, self.slot, envelope)

    def prepare(self, envelope):
        proposal = self._proposal(envelope)
        view, value = proposal["view"], proposal["value"]
        if view != self.state["view"]:
            raise ProtocolError("HotStuff prepare is not in current view")
        locked = self.state.get("locked_qc")
        justify = proposal["justify"]
        if (locked is not None and digest(value) != locked["body"]["value"]
                and (justify is None or justify["body"]["view"] <= locked["body"]["view"])):
            raise ProtocolError("HotStuff proposal violates lock")
        self._remember(value, proposal["command"])
        vote = self._vote("prepare", view, digest(value))
        self.state["proposals"][str(view)] = copy.deepcopy(envelope)
        return vote

    def precommit(self, envelope, prepare_qc):
        proposal = self._proposal(envelope)
        view, hashed = proposal["view"], digest(proposal["value"])
        check_qc(self.p, self.registry, self.slot, prepare_qc, "prepare", view=view, value_hash=hashed)
        if view != self.state["view"]:
            raise ProtocolError("HotStuff precommit is not in current view")
        self._remember(proposal["value"], proposal["command"])
        vote = self._vote("precommit", view, hashed)
        self._learn_prepare(prepare_qc)
        self.state["proposals"][str(view)] = copy.deepcopy(envelope)
        return vote

    def commit(self, envelope, prepare_qc, precommit_qc):
        proposal = self._proposal(envelope)
        view, hashed = proposal["view"], digest(proposal["value"])
        check_qc(self.p, self.registry, self.slot, prepare_qc, "prepare", view=view, value_hash=hashed)
        check_qc(self.p, self.registry, self.slot, precommit_qc, "precommit", view=view, value_hash=hashed)
        if view != self.state["view"]:
            raise ProtocolError("HotStuff commit is not in current view")
        self._remember(proposal["value"], proposal["command"])
        vote = self._vote("commit", view, hashed)
        self._learn_prepare(prepare_qc)
        self.state["locked_qc"] = copy.deepcopy(precommit_qc)
        self.state["proposals"][str(view)] = copy.deepcopy(envelope)
        return vote

    def decide(self, value, command, commit_qc):
        check_decision(self.p, self.registry, value, commit_qc)
        old = self.state.get("decision")
        if old is not None and old["body"]["value"] != digest(value):
            raise ProtocolError("conflicting HotStuff decision")
        self._remember(value, command)
        self.state["decision"] = copy.deepcopy(commit_qc)


async def run_round(p, registry, value, command, call, *, view_attempts=None):
    """Transport-neutral bounded driver; callers may resume with durable status.

    call(names, request) returns independently signed replies. This driver
    is not a pacemaker: it has no distributed timeout/new-view synchronizer.
    """
    slot = slot_for(value)
    base = {"action": "hotstuff", "slot": slot}

    async def finish_proposal(proposal, view):
        proposed = check_proposal(p, registry, slot, proposal)
        if proposed["view"] != view:
            raise ProtocolError("HotStuff proposal differs from active view")
        chosen, chosen_command = proposed["value"], proposed["command"]
        hashed = digest(chosen)
        votes = await call(p.aggregators, {**base, "op": "prepare", "proposal": proposal})
        prepare_qc = make_qc(p, registry, vote_claim(p, slot, "prepare", view, hashed), votes)
        votes = await call(p.aggregators, {**base, "op": "precommit", "proposal": proposal,
                                          "prepare_qc": prepare_qc})
        precommit_qc = make_qc(p, registry, vote_claim(p, slot, "precommit", view, hashed), votes)
        votes = await call(p.aggregators, {**base, "op": "commit", "proposal": proposal,
                                          "prepare_qc": prepare_qc, "precommit_qc": precommit_qc})
        commit_qc = make_qc(p, registry, vote_claim(p, slot, "commit", view, hashed), votes)
        votes = await call(p.aggregators, {**base, "op": "decide", "value": chosen,
                                          "command": chosen_command, "commit_qc": commit_qc})
        result = make_qc(p, registry, chosen, votes)
        result["hotstuff"] = commit_qc
        return result

    async def resume_view(view):
        """Retry idempotent votes for a signed proposal left in this view."""
        reports = await call(p.aggregators, {**base, "op": "recover"})
        candidates = []
        seen = set()
        for report in reports:
            try:
                body = check_recovery(p, registry, slot, report)
                proposal = body["proposal"]
                if body["view"] != view or proposal is None:
                    continue
                hashed = digest(proposal)
                if hashed not in seen:
                    seen.add(hashed)
                    candidates.append((body["prepare_qc"] is not None, proposal))
            except (ProtocolError, KeyError, TypeError):
                continue
        for _prepared, proposal in sorted(candidates, key=lambda item: item[0], reverse=True):
            try:
                return await finish_proposal(proposal, view)
            except (ProtocolError, KeyError, TypeError):
                continue
        raise ProtocolError("HotStuff current-view proposal unavailable")

    async def observe(*, drain=False):
        """Read certified peer progress, including a decision made elsewhere."""
        reports = await call(p.aggregators, {**base, "op": "status", "drain": drain})
        latest_view, latest_enter_qc = 0, None
        for report in reports:
            try:
                body = check_status(p, registry, slot, report)
                if body["decision"] is not None:
                    entry = body["entry"]
                    votes = await call(p.aggregators, {**base, "op": "decide", **entry,
                                                      "commit_qc": body["decision"]})
                    result = make_qc(p, registry, entry["value"], votes)
                    result["hotstuff"] = body["decision"]
                    return latest_view, latest_enter_qc, result
                if body["view"] > latest_view:
                    latest_view, latest_enter_qc = body["view"], body["timeout_qc"]
            except (ProtocolError, KeyError, TypeError):
                continue
        return latest_view, latest_enter_qc, None

    latest_view, latest_enter_qc, decided = await observe()
    if decided is not None:
        return decided
    # A restart may have interrupted any phase. Enter a fresh view so that
    # every prepared value can be recovered through new-view evidence.
    start = max(1, latest_view)
    attempts = len(p.aggregators) if view_attempts is None else view_attempts
    if type(attempts) is not int or attempts < 1:
        raise ProtocolError("invalid HotStuff driver attempts")
    view, enter_qc = start, latest_enter_qc
    for _ in range(attempts):
        try:
            messages = await call(p.aggregators, {**base, "op": "new_view", "view": view,
                                                  "timeout_qc": enter_qc})
            highest_new_view(p, registry, slot, view, messages)
            proposals = await call((p.leader(view - 1),), {**base, "op": "propose", "view": view,
                                  "messages": messages, "value": value, "command": command})
            if len(proposals) != 1:
                raise ProtocolError("HotStuff leader unavailable")
            return await finish_proposal(proposals[0], view)
        except (ProtocolError, KeyError, TypeError):
            try:
                return await resume_view(view)
            except (ProtocolError, KeyError, TypeError):
                pass
            # No remote caller can advance an honest replica's view alone.
            # Replicas enforce their own durable timer. A restarted driver
            # must not start that timer over: an aged view may already be
            # eligible to time out. Probe and retry boundedly while observing
            # decisions or a certified higher view.
            deadline = time.monotonic() + math.ldexp(0.5, min(view - 1, 1023))
            advanced = False
            while True:
                higher_view, higher_qc, decided = await observe()
                if decided is not None:
                    return decided
                if higher_view > view:
                    view, enter_qc = higher_view, higher_qc
                    advanced = True
                    break
                votes = await call(p.aggregators, {**base, "op": "timeout", "view": view})
                try:
                    enter_qc = make_timeout_qc(p, registry, slot, view, votes)
                    break
                except ProtocolError as exc:
                    # A slow peer may have entered a later certified view
                    # after our fast status quorum replied.
                    higher_view, higher_qc, decided = await observe(drain=True)
                    if decided is not None:
                        return decided
                    if higher_view > view:
                        view, enter_qc = higher_view, higher_qc
                        advanced = True
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProtocolError("HotStuff timeout quorum unavailable") from exc
                    await asyncio.sleep(min(remaining, 1.0))
            if advanced:
                continue
        view += 1
    # Another concurrent recovery driver can commit while this driver uses
    # its last local attempt. Re-read all peer statuses before surfacing a
    # retryable exhaustion, so an already certified decision is not lost.
    _, _, decided = await observe(drain=True)
    if decided is not None:
        return decided
    raise ProtocolError("HotStuff driver exhausted views; durable QCs retained")

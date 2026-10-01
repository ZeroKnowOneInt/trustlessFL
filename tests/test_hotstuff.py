"""HotStuff quorum, persistence, view recovery, and Flower integration."""

import asyncio
import copy
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from trustlessfl.client_app import process_local_request
from trustlessfl.crypto import Identity, ProtocolError, digest, verify
from trustlessfl.demo import provision
from trustlessfl.hotstuff import (HotStuffSlot, check_decision, check_recovery, make_qc,
                                  make_timeout_qc, run_round, slot_for,
                                  timeout_claim, vote_claim)
from trustlessfl.local_grid import ProcessGrid
from trustlessfl.protocol import Parameters, check_finalized_model
from trustlessfl.workflow import AionWorkflow


def test_hotstuff_driver_observes_decision_after_last_view_attempt(monkeypatch):
    from trustlessfl import hotstuff

    p = Parameters("hs-concurrent-final-decision", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), hotstuff=True)
    value = p.claim("roster", 1, parent="a" * 64, members=list(p.clients),
                    updates="b" * 64, late="")
    command = {"action": "prepare", "value": value}
    state = {"timed_out": False, "status_reads": 0}

    def timeout_qc(*args):
        state["timed_out"] = True
        return {"body": "timeout"}

    async def call(names, request):
        if request["op"] == "status":
            state["status_reads"] += 1
            return [{"signed": True}] if state["timed_out"] else []
        if request["op"] == "decide":
            return [{"signed": True}] * p.quorum
        return []

    monkeypatch.setattr(hotstuff, "make_timeout_qc", timeout_qc)
    monkeypatch.setattr(hotstuff, "check_status", lambda *args: {
        "decision": {"body": "commit"}, "entry": {"value": value, "command": command},
        "view": 1, "timeout_qc": None})
    monkeypatch.setattr(hotstuff, "make_qc", lambda *args: {"body": value})
    result = asyncio.run(run_round(p, {}, value, command, call, view_attempts=1))
    assert result["body"] == value
    assert result["hotstuff"] == {"body": "commit"}
    assert state["status_reads"] >= 3


def test_legacy_task_commitment_is_unchanged_by_opt_in_hotstuff_field():
    p = Parameters("hs-opt-in", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    legacy = asdict(p)
    legacy.pop("original_hprf_setup")
    legacy.pop("oracle_mgf")
    legacy.pop("hotstuff")
    legacy.pop("hprf_input_bits")
    for name in ("mgf_beta", "mgf_initial_alpha", "mgf_initial_bound", "mgf_initial_term"):
        legacy.pop(name)
    for name in ("mgf_projection", "mgf_single_view", "mgf_percentile",
                 "mgf_artifact_bound", "mgf_mask_sum_norm"):
        legacy.pop(name)
    assert p.config_digest == digest(legacy)
    assert p.config_digest == "ab69ce32adef1ba904df05c9fd9c562aa0d2eed7e0db468134ba5f6b23fd8afb"
    assert Parameters.from_dict({**asdict(p), "hotstuff": True}).config_digest != p.config_digest


@pytest.fixture
def validation_context():
    p = Parameters("hs-validation", ("c0", "c1"), ("a0", "a1", "a2", "a3"), hotstuff=True)
    identities = {name: Identity.generate(name) for name in p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    value = p.claim("roster", 1, parent="a" * 64, members=["c0", "c1"], updates="b" * 64, late="")
    calls = []
    def validate(candidate, command):
        calls.append(True)
        if command != {"value": candidate}:
            raise ProtocolError("invalid command")
    return p, identities, registry, value, calls, validate


@pytest.mark.parametrize("reuse", [False, True])
def test_hotstuff_local_validation_reuse_is_explicit_and_restart_safe(validation_context, reuse):
    p, identities, registry, value, calls, validate = validation_context
    state = {}
    engine = HotStuffSlot(identities["a0"], p, registry, slot_for(value), state, validate,
                         reuse_validation=reuse)
    command = {"value": value}
    engine._remember(value, command)
    restarted = HotStuffSlot(identities["a0"], p, registry, slot_for(value),
        json.loads(json.dumps(state)), validate, reuse_validation=reuse)
    restarted._remember(value, command)
    assert len(calls) == (1 if reuse else 2)
    with pytest.raises(ProtocolError, match="invalid command"):
        restarted._remember(value, {**command, "changed": True})
    assert len(calls) == (2 if reuse else 3)
    other = {**value, "members": ["c1"]}
    restarted._remember(other, {"value": other})
    assert len(calls) == (3 if reuse else 4)


def test_hotstuff_local_validation_cannot_be_transferred_or_rebound(validation_context):
    p, identities, registry, value, calls, validate = validation_context
    state = {}
    HotStuffSlot(identities["a0"], p, registry, slot_for(value), state, validate,
                reuse_validation=True)._remember(value, {"value": value})
    other_recipient = HotStuffSlot(identities["a1"], p, registry, slot_for(value),
                                 copy.deepcopy(state), validate, reuse_validation=True)
    with pytest.raises(ProtocolError, match="signature"):
        other_recipient._remember(value, {"value": value})
    changed = copy.deepcopy(state)
    proof = changed["values"][digest(value)]["validation"]
    proof["body"]["command"] = "c" * 64
    changed["values"][digest(value)]["validation"] = identities["a0"].sign(proof["body"])
    rebound = HotStuffSlot(identities["a0"], p, registry, slot_for(value), changed,
                          validate, reuse_validation=True)
    with pytest.raises(ProtocolError, match="validation proof"):
        rebound._remember(value, {"value": value})
    assert len(calls) == 1


def test_hotstuff_legacy_validation_entry_is_rechecked(validation_context):
    p, identities, registry, value, calls, validate = validation_context
    state = {"values": {digest(value): {"value": value, "command": {"value": value}}}}
    engine = HotStuffSlot(identities["a0"], p, registry, slot_for(value), state, validate,
                         reuse_validation=True)
    engine._remember(value, {"value": value})
    assert len(calls) == 1 and "validation" in state["values"][digest(value)]
    with pytest.raises(ProtocolError, match="another slot"):
        engine._remember({**value, "parent": "c" * 64}, {"value": value})
    assert len(calls) == 1


def test_hotstuff_reusable_validation_requires_read_only_callback(validation_context):
    p, identities, registry, value, _calls, _validate = validation_context
    state = {}
    def mutate(_value, command):
        command["changed"] = True
    engine = HotStuffSlot(identities["a0"], p, registry, slot_for(value), state, mutate,
                         reuse_validation=True)
    command = {"value": value}
    with pytest.raises(ProtocolError, match="mutated application inputs"):
        engine._remember(value, command)
    assert state["values"] == {} and command == {"value": value}


def test_hotstuff_validation_reuse_preserves_all_three_vote_qcs(validation_context):
    p, identities, registry, value, _calls, _validate = validation_context
    slot, command = slot_for(value), {"value": value}
    def run(reuse):
        states = {name: {} for name in p.aggregators}
        calls = []
        def validate(candidate, requested):
            calls.append(True)
            if candidate != value or requested != command:
                raise ProtocolError("invalid command")
        def engine(name):
            return HotStuffSlot(identities[name], p, registry, slot, states[name], validate,
                                reuse_validation=reuse)
        views = [engine(name).new_view(1) for name in p.aggregators]
        proposal = engine("a0").propose(1, views, value, command)
        prepares = [engine(name).prepare(proposal) for name in p.aggregators]
        prepare_qc = make_qc(p, registry, vote_claim(p, slot, "prepare", 1, digest(value)), prepares)
        precommits = [engine(name).precommit(proposal, prepare_qc) for name in p.aggregators]
        precommit_qc = make_qc(p, registry, vote_claim(p, slot, "precommit", 1, digest(value)), precommits)
        commits = [engine(name).commit(proposal, prepare_qc, precommit_qc) for name in p.aggregators]
        commit_qc = make_qc(p, registry, vote_claim(p, slot, "commit", 1, digest(value)), commits)
        for name in p.aggregators:
            engine(name).decide(value, command, commit_qc)
            assert states[name]["decision"] == commit_qc
        return (proposal, prepare_qc, precommit_qc, commit_qc), len(calls)
    original, original_calls = run(False)
    optimized, optimized_calls = run(True)
    assert optimized == original
    assert original_calls == 17 and optimized_calls == 4


@pytest.mark.parametrize("stage", ["prepare", "precommit", "commit"])
def test_local_hotstuff_validation_proofs_are_not_vote_qcs(validation_context, stage):
    p, identities, registry, value, _calls, validate = validation_context
    slot = slot_for(value)
    proofs = []
    for name in p.aggregators:
        state = {}
        HotStuffSlot(identities[name], p, registry, slot, state, validate,
                    reuse_validation=True)._remember(value, {"value": value})
        proofs.append(state["values"][digest(value)]["validation"])
    # Even n valid aggregator signatures on application-validation claims do
    # not certify a prepare/precommit/commit vote or permit skipping a phase.
    with pytest.raises(ProtocolError):
        make_qc(p, registry, vote_claim(p, slot, stage, 1, digest(value)), proofs)


def test_hotstuff_restart_recovers_prepared_value_and_prevents_double_votes():
    p = Parameters("hs-restart", ("c0", "c1"), ("a0", "a1", "a2", "a3"), hotstuff=True)
    identities = {name: Identity.generate(name) for name in p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parent = "a" * 64
    a = p.claim("roster", 1, parent=parent, members=["c0"], updates="b" * 64, late="")
    b = p.claim("roster", 1, parent=parent, members=["c1"], updates="c" * 64, late="")
    slot = slot_for(a)
    command_a, command_b = {"value": a}, {"value": b}
    states = {name: {} for name in p.aggregators}

    def engine(name):
        return HotStuffSlot(identities[name], p, registry, slot, states[name],
                            lambda value, command: None if command == {"value": value}
                            and value in (a, b) else (_ for _ in ()).throw(ProtocolError("invalid command")))

    names = p.aggregators
    new_views = [engine(name).new_view(1) for name in names]
    proposal = engine("a0").propose(1, new_views, a, command_a)
    prepare = [engine(name).prepare(proposal) for name in names[:3]]
    with pytest.raises(ProtocolError, match="double vote"):
        engine("a0").prepare(identities["a0"].sign({
            **verify(proposal, registry), "value": b, "command": command_b}))
    prepare_qc = make_qc(p, registry, vote_claim(p, slot, "prepare", 1, digest(a)), prepare)
    precommits = [engine(name).precommit(proposal, prepare_qc) for name in names[:3]]
    precommit_qc = make_qc(p, registry, vote_claim(p, slot, "precommit", 1, digest(a)), precommits)
    report = engine("a0").recover()
    assert check_recovery(p, registry, slot, report)["prepare_qc"] == prepare_qc
    conflicting_proposal = identities["a0"].sign({
        **verify(proposal, registry), "value": b, "command": command_b})
    with pytest.raises(ProtocolError, match="differs from proposal"):
        check_recovery(p, registry, slot, identities["a0"].sign({
            **verify(report, registry), "proposal": conflicting_proposal}))
    # The leader disappears after some replicas lock. No commit QC is sent.
    for name in names[:3]:
        engine(name).commit(proposal, prepare_qc, precommit_qc)
    states["a0"] = json.loads(json.dumps(states["a0"]))  # persisted and restarted
    assert states["a0"]["locked_qc"]["body"]["value"] == digest(a)
    with pytest.raises(ProtocolError, match="timeout QC"):
        engine("a0").new_view(2)
    with pytest.raises(ProtocolError, match="not timed out"):
        engine("a0").timeout(1)
    for state in states.values():
        state["view_started_at"] -= 1  # controlled local timer expiry
    timeout_qc = make_timeout_qc(p, registry, slot, 1,
                                 [engine(name).timeout(1) for name in names[:3]])
    new_views = [engine(name).new_view(2, timeout_qc) for name in names]
    recovered = engine("a1").propose(2, new_views, b, command_b)
    assert verify(recovered, registry, sender="a1")["value"] == a
    with pytest.raises(ProtocolError, match="ignores high QC"):
        engine("a0").prepare(identities["a1"].sign({
            **verify(recovered, registry), "value": b, "command": command_b}))
    prepare = [engine(name).prepare(recovered) for name in names[:3]]
    prepare_qc = make_qc(p, registry, vote_claim(p, slot, "prepare", 2, digest(a)), prepare)
    precommits = [engine(name).precommit(recovered, prepare_qc) for name in names[:3]]
    precommit_qc = make_qc(p, registry, vote_claim(p, slot, "precommit", 2, digest(a)), precommits)
    commits = [engine(name).commit(recovered, prepare_qc, precommit_qc) for name in names[:3]]
    commit_qc = make_qc(p, registry, vote_claim(p, slot, "commit", 2, digest(a)), commits)
    for name in names[:3]:
        engine(name).decide(a, command_a, commit_qc)
    check_decision(p, registry, a, commit_qc)
    with pytest.raises(ProtocolError):
        check_decision(p, registry, b, commit_qc)
    assert verify(engine("a0").status(), registry)["decision"] == commit_qc


@pytest.mark.parametrize("advance_after_status,hide_ahead_on_fast",
                         [(False, False), (True, False), (False, True)])
def test_hotstuff_driver_joins_higher_view_after_old_leader_crashes(
        advance_after_status, hide_ahead_on_fast):
    p = Parameters("hs-ahead-replica", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), hotstuff=True)
    identities = {name: Identity.generate(name) for name in p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    value = p.claim("roster", 1, parent="a" * 64, members=list(p.clients),
                    updates="b" * 64, late="")
    command = {"action": "prepare", "value": value}
    slot = slot_for(value)
    states = {name: {} for name in p.aggregators}

    def validate(candidate, requested):
        if candidate != value or requested != command:
            raise ProtocolError("unexpected application value")

    def engine(name):
        return HotStuffSlot(identities[name], p, registry, slot, states[name], validate)

    for name in p.aggregators:
        engine(name).new_view(1)
    for name in ("a0", "a1", "a3"):
        states[name]["view_started_at"] -= 1
    timeout_qc = make_timeout_qc(p, registry, slot, 1,
                                 [engine(name).timeout(1) for name in ("a0", "a1", "a3")])
    assert timeout_qc["body"] == timeout_claim(p, slot, 1)
    if not advance_after_status:
        engine("a3").new_view(2, timeout_qc)
    # a0 disappears. a3 may enter view 2 before or just after the first
    # status read; a1/a2 cannot make a fresh view-1 timeout QC alone.
    advanced = False

    async def call(names, request):
        nonlocal advanced
        if advance_after_status and request["op"] == "new_view" and not advanced:
            engine("a3").new_view(2, timeout_qc)
            advanced = True
        replies = []
        for name in names:
            if name == "a0":
                continue
            replica = engine(name)
            op = request["op"]
            if (op == "status" and name == "a3" and hide_ahead_on_fast
                    and not request.get("drain")):
                continue
            try:
                if op == "status":
                    reply = replica.status()
                elif op == "recover":
                    reply = replica.recover()
                elif op == "new_view":
                    reply = replica.new_view(request["view"], request["timeout_qc"])
                elif op == "propose":
                    reply = replica.propose(request["view"], request["messages"],
                                            request["value"], request["command"])
                elif op == "prepare":
                    reply = replica.prepare(request["proposal"])
                elif op == "precommit":
                    reply = replica.precommit(request["proposal"], request["prepare_qc"])
                elif op == "commit":
                    reply = replica.commit(request["proposal"], request["prepare_qc"],
                                           request["precommit_qc"])
                elif op == "decide":
                    replica.decide(request["value"], request["command"], request["commit_qc"])
                    reply = identities[name].sign(request["value"])
                elif op == "timeout":
                    reply = replica.timeout(request["view"])
                else:
                    raise AssertionError(op)
            except ProtocolError:
                continue
            replies.append(reply)
        return replies

    result = asyncio.run(run_round(p, registry, value, command, call))
    assert result["body"] == value
    assert result["hotstuff"]["body"]["view"] == 2
    assert not advance_after_status or advanced
    assert all(states[name]["decision"] == result["hotstuff"]
               for name in ("a1", "a2", "a3"))


def test_hotstuff_driver_resumes_aged_view_without_restarting_timer(monkeypatch):
    import trustlessfl.hotstuff as hotstuff_module

    p = Parameters("hs-aged-view", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), hotstuff=True)
    identities = {name: Identity.generate(name) for name in p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    value = p.claim("roster", 1, parent="a" * 64, members=list(p.clients),
                    updates="b" * 64, late="")
    command = {"action": "prepare", "value": value}
    slot = slot_for(value)
    states = {name: {} for name in p.aggregators}

    def engine(name):
        return HotStuffSlot(identities[name], p, registry, slot, states[name],
                            lambda candidate, requested: None if candidate == value
                            and requested == command else (_ for _ in ()).throw(
                                ProtocolError("invalid application value")))

    for name in ("a1", "a2", "a3"):
        engine(name).new_view(1)
        states[name]["view_started_at"] -= 1

    async def no_sleep(_delay):
        raise AssertionError("expired peer timer must not be restarted by driver")

    monkeypatch.setattr(hotstuff_module.asyncio, "sleep", no_sleep)
    timeout_requests = []
    interrupted = False

    async def call(names, request):
        nonlocal interrupted
        if request["op"] == "timeout":
            timeout_requests.append(request["view"])
        replies = []
        for name in names:
            if name == "a0":
                continue
            replica = engine(name)
            op = request["op"]
            try:
                if op == "status":
                    reply = replica.status()
                elif op == "recover":
                    reply = replica.recover()
                elif op == "new_view":
                    reply = replica.new_view(request["view"], request["timeout_qc"])
                elif op == "propose":
                    reply = replica.propose(request["view"], request["messages"],
                                            request["value"], request["command"])
                elif op == "prepare":
                    reply = replica.prepare(request["proposal"])
                elif op == "precommit":
                    reply = replica.precommit(request["proposal"], request["prepare_qc"])
                elif op == "commit":
                    reply = replica.commit(request["proposal"], request["prepare_qc"],
                                           request["precommit_qc"])
                elif op == "decide":
                    replica.decide(request["value"], request["command"], request["commit_qc"])
                    reply = identities[name].sign(request["value"])
                elif op == "timeout":
                    reply = replica.timeout(request["view"])
                else:
                    raise AssertionError(op)
            except ProtocolError:
                continue
            replies.append(reply)
        if request["op"] == "precommit" and not interrupted:
            interrupted = True
            raise asyncio.CancelledError("driver stopped after persisted pre-commit votes")
        return replies

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run_round(p, registry, value, command, call))
    assert all("precommit/2" in states[name]["votes"] for name in ("a1", "a2", "a3"))
    result = asyncio.run(run_round(p, registry, value, command, call))
    assert result["body"] == value
    assert result["hotstuff"]["body"]["view"] == 2
    assert timeout_requests == [1]


@pytest.mark.parametrize("peer_advances_while_waiting", [False, True])
def test_hotstuff_driver_waits_for_actual_higher_view_timeout(peer_advances_while_waiting):
    p = Parameters("hs-view-three-timer", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), hotstuff=True)
    identities = {name: Identity.generate(name) for name in p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    value = p.claim("roster", 1, parent="a" * 64, members=list(p.clients),
                    updates="b" * 64, late="")
    command = {"action": "prepare", "value": value}
    slot = slot_for(value)
    states = {name: {} for name in p.aggregators}

    def engine(name):
        return HotStuffSlot(identities[name], p, registry, slot, states[name],
                            lambda candidate, requested: None if candidate == value
                            and requested == command else (_ for _ in ()).throw(
                                ProtocolError("invalid application value")))

    for name in p.aggregators:
        engine(name).new_view(1)
    for old_view, elapsed in ((1, 1), (2, 2)):
        for name in p.aggregators:
            states[name]["view_started_at"] -= elapsed
        qc = make_timeout_qc(p, registry, slot, old_view,
                             [engine(name).timeout(old_view) for name in p.aggregators])
        for name in p.aggregators:
            engine(name).new_view(old_view + 1, qc)
    # View 3's leader a2 disappears just after the three honest replicas
    # enter. Their local timeout cannot be signed until two full seconds.
    assert p.leader(2) == "a2"
    qc3 = None
    if peer_advances_while_waiting:
        # A quorum can have timed out locally before the driver observes it.
        for name in ("a0", "a2", "a3"):
            states[name]["view_started_at"] -= 3
        qc3 = make_timeout_qc(p, registry, slot, 3,
                              [engine(name).timeout(3) for name in ("a0", "a2", "a3")])
    status_reads, timeout_requests = 0, []

    async def call(names, request):
        nonlocal status_reads
        if request["op"] == "status":
            status_reads += 1
            if peer_advances_while_waiting and status_reads == 2:
                engine("a3").new_view(4, qc3)
        elif request["op"] == "timeout":
            timeout_requests.append(request["view"])
        replies = []
        for name in names:
            if name == "a2":
                continue
            replica = engine(name)
            try:
                op = request["op"]
                if op == "status":
                    reply = replica.status()
                elif op == "recover":
                    reply = replica.recover()
                elif op == "new_view":
                    reply = replica.new_view(request["view"], request["timeout_qc"])
                elif op == "propose":
                    reply = replica.propose(request["view"], request["messages"],
                                            request["value"], request["command"])
                elif op == "prepare":
                    reply = replica.prepare(request["proposal"])
                elif op == "precommit":
                    reply = replica.precommit(request["proposal"], request["prepare_qc"])
                elif op == "commit":
                    reply = replica.commit(request["proposal"], request["prepare_qc"],
                                           request["precommit_qc"])
                elif op == "timeout":
                    reply = replica.timeout(request["view"])
                elif op == "decide":
                    replica.decide(request["value"], request["command"], request["commit_qc"])
                    reply = identities[name].sign(request["value"])
                else:
                    raise AssertionError(op)
            except ProtocolError:
                continue
            replies.append(reply)
        return replies

    result = asyncio.run(run_round(p, registry, value, command, call))
    assert result["body"] == value
    assert result["hotstuff"]["body"]["view"] == 4
    if peer_advances_while_waiting:
        assert status_reads >= 2
        assert 3 not in timeout_requests


def test_hotstuff_view_timer_distinguishes_process_restart_from_reboot(monkeypatch):
    import trustlessfl.hotstuff as hotstuff_module

    p = Parameters("hs-clock-epoch", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), hotstuff=True)
    identity = Identity.generate("a0")
    registry = {"a0": identity.public()}
    slot = {"phase": "roster", "round": 1, "context": "a" * 64}
    state = {}

    def engine():
        return HotStuffSlot(identity, p, registry, slot, state, lambda _value, _command: None)

    engine().new_view(1)
    saved_epoch = state["view_clock_epoch"]
    # A new Party instance in the same boot retains the original timer.
    state["view_started_at"] -= 10
    assert verify(engine().timeout(1), registry)["view"] == 1
    # The new boot can have a larger monotonic value than the old saved one.
    # A timestamp comparison alone would incorrectly allow immediate timeout.
    state["view_started_at"] = 1
    monkeypatch.setattr(hotstuff_module, "_CLOCK_EPOCH", saved_epoch + "-reboot")
    with pytest.raises(ProtocolError, match="not timed out"):
        engine().timeout(1)
    assert state["view_clock_epoch"] != saved_epoch
    monkeypatch.setattr(hotstuff_module, "_CLOCK_EPOCH", None)
    with pytest.raises(ProtocolError, match="persistent monotonic clock epoch"):
        engine()


def test_hotstuff_flower_certificates_bind_application_rounds(tmp_path):
    p = Parameters("hs-flower", ("c0", "c1"), ("a0", "a1", "a2", "a3"), hotstuff=True)
    manifest_path, nodes = provision(tmp_path / "identities", p)
    registry = json.loads(manifest_path.read_text())["registry"]
    with ProcessGrid(nodes) as grid:
        history = AionWorkflow(p, registry, timeout=45.0).run(grid, 2)
    assert [entry["body"]["round"] for entry in history] == [0, 1, 2]
    for model in history[1:]:
        check_finalized_model(model, p, registry)
        assert model["hotstuff"]["body"]["stage"] == "commit"
        altered = copy.deepcopy(model)
        altered.pop("hotstuff")
        with pytest.raises(ProtocolError):
            check_finalized_model(altered, p, registry)
    config = nodes[3]  # a0
    status = process_local_request(config, {"action": "roster_proof"})
    body = verify(status, registry, sender="a0")
    assert body["hotstuff"]["body"]["phase"] == "roster"
    assert body["candidate"]["round"] == 2
    state_path, = (Path(config["aion-identity"]).parent).glob("state-*.json")
    inode = state_path.stat().st_ino
    model_status = process_local_request(config, {"action": "model_status"})
    assert verify(model_status, registry, sender="a0")["model"]["round"] == 2
    assert state_path.stat().st_ino == inode


def test_hotstuff_rejects_certificates_for_another_phase_or_parent():
    p = Parameters("hs-context", ("c0", "c1"), ("a0", "a1", "a2", "a3"), hotstuff=True)
    identities = {name: Identity.generate(name) for name in p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    value = p.claim("roster", 1, parent="a" * 64, members=list(p.clients), updates="b" * 64, late="")
    slot = slot_for(value)
    body = vote_claim(p, slot, "commit", 1, digest(value))
    qc = make_qc(p, registry, body, [identity.sign(body) for identity in identities.values()])
    check_decision(p, registry, value, qc)
    for altered in ({**value, "parent": "c" * 64},
                    {**value, "round": 2},
                    {**value, "members": ["c0"]}):
        with pytest.raises(ProtocolError):
            check_decision(p, registry, altered, qc)

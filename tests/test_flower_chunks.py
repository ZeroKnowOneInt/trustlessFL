"""Large signed AION requests and responses still travel in bounded Flower messages."""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from trustlessfl import flower_chunks
from trustlessfl.client_app import payload, save_state
from trustlessfl.crypto import Identity, ProtocolError, canonical, digest, verify
from trustlessfl.demo import provision
from trustlessfl.local_grid import ProcessGrid
from trustlessfl.protocol import Parameters
from trustlessfl.workflow import AionWorkflow


def config(tmp_path):
    p = Parameters("flower-chunk-test", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    manifest_path, nodes = provision(tmp_path / "identities", p)
    return p, json.loads(manifest_path.read_text())["registry"], nodes


def test_chunk_upload_retries_and_rejects_conflicts(tmp_path, monkeypatch):
    p, registry, nodes = config(tmp_path)
    monkeypatch.setattr(flower_chunks, "CHUNK_BYTES", 64)
    command = {"action": "hello", "padding": "abc" * 100, "runtime-case": "paper-case"}
    raw = canonical(command)
    tag = hashlib.sha256(raw).hexdigest()

    def write(offset, data=None):
        return flower_chunks.transport_request(nodes[1], {
            "action": "wire_write", "digest": tag, "size": len(raw), "offset": offset,
            "data": base64.b64encode(raw[offset:offset + 64] if data is None else data).decode()})

    first, _ = write(0)
    again, _ = write(0)
    assert first == again
    assert verify(first, registry) == p.claim("wire-stored", 0, digest=tag,
                                             size=len(raw), offset=0, length=64)
    with pytest.raises(ProtocolError, match="conflicting"):
        write(0, b"z" * 64)
    with pytest.raises(ProtocolError, match="out-of-order"):
        write(128)
    for offset in range(64, len(raw), 64):
        write(offset)
    request = {"action": "wire_execute", "digest": tag, "size": len(raw)}
    assert flower_chunks.transport_request(nodes[1], request) == (None, command)
    flower_chunks.transport_request(nodes[1], {**request, "action": "wire_release", "direction": "in"})
    with pytest.raises(ProtocolError, match="missing"):
        flower_chunks.transport_request(nodes[1], request)


def test_chunk_transport_rejects_bad_hash_and_path(tmp_path):
    _, _, nodes = config(tmp_path)
    raw = canonical({"action": "hello"})
    request = {"action": "wire_write", "digest": "0" * 64, "size": len(raw),
               "offset": 0, "data": base64.b64encode(raw).decode()}
    with pytest.raises(ProtocolError, match="digest mismatch"):
        flower_chunks.transport_request(nodes[1], request)
    with pytest.raises(ProtocolError, match="descriptor"):
        flower_chunks.transport_request(nodes[1], {**request, "digest": "../" + "a" * 61})
    with pytest.raises(ProtocolError, match="offset"):
        flower_chunks.transport_request(nodes[1], {**request, "offset": -1})


class RecordingGrid(ProcessGrid):
    def __init__(self, nodes):
        super().__init__(nodes)
        self.actions = []

    def send_and_receive(self, messages, *, timeout=None):
        messages = list(messages)
        for message in messages:
            command = payload(message)
            assert len(canonical(command)) <= flower_chunks.PAYLOAD_LIMIT
            self.actions.append(command["action"])
        for reply in super().send_and_receive(messages, timeout=timeout):
            if not reply.has_error():
                assert len(canonical(payload(reply))) <= flower_chunks.PAYLOAD_LIMIT
            yield reply


def test_real_flower_message_roundtrip_above_payload_limit(tmp_path):
    p, registry, nodes = config(tmp_path)
    workflow = AionWorkflow(p, registry, timeout=60)
    with RecordingGrid(nodes) as grid:
        workflow.discover(grid)
        enrollments = workflow.call(grid, p.clients, "enroll")
        genesis = workflow.quorum_call(grid, "initialize", enrollments=enrollments)
        padding = "x" * (flower_chunks.PAYLOAD_LIMIT + 1024)
        replies = workflow.call(grid, ("c0",), "hello", padding=padding,
                                **{"runtime-case": "paper-case"})
        assert len(replies) == 1 and replies[0]["sender"] == "c0"
        identity_path = Path(nodes[1]["aion-identity"])
        identity = Identity.from_private(json.loads(identity_path.read_text()))
        response = identity.sign(p.claim("update", 1, parent=digest(genesis["body"]),
                                          vector=[0] * p.dimension, padding=padding))
        state_path = identity_path.parent / ("state-" + digest({"task": p.task, "party": "c0"}) + ".json")
        state = json.loads(state_path.read_text())
        state["updates"] = {"1": response}
        save_state(state_path, state)
        assert workflow.call(grid, ("c0",), "train", model=genesis) == [response]
        second, = workflow.call(grid, ("c1",), "train", model=genesis)
        prepared = workflow._prepare_payload(grid, genesis, [response, second], None)
        assert "staged" in prepared
        roster = workflow.quorum_call(grid, "prepare", **prepared)
        assert roster["body"]["updates"] == digest([response, second])
        assert "wire_execute" in grid.actions and "wire_read" in grid.actions
        assert "wire_release" in grid.actions
        assert not list(identity_path.parent.glob("flower-wire-*/*.bin"))

"""Offline process-isolated Flower Grid harness, without Ray or a SuperLink.

Uses real Flower Message serialization and ClientApp/ServerApp entrypoints.
This is a local test transport, not a network deployment or an OS trust boundary.
"""

import multiprocessing as mp
import time
import uuid

from flwr.app import Context, Message, Metadata, RecordDict
from flwr.common.serde import message_from_proto, message_to_proto
from flwr.proto.message_pb2 import Message as MessageProto
from flwr.serverapp import Grid


def serialize(message: Message) -> bytes:
    return message_to_proto(message).SerializeToString()


def deserialize(data: bytes) -> Message:
    return message_from_proto(MessageProto.FromString(data))


def _worker(connection, node_id: int, node_config: dict):
    from .client_app import app
    context = Context(run_id=1, node_id=node_id, node_config=node_config,
                      state=RecordDict(), run_config={})
    try:
        while True:
            data = connection.recv_bytes()
            if not data:
                break
            reply = app(deserialize(data), context)
            connection.send_bytes(serialize(reply))
    finally:
        connection.close()


class ProcessGrid(Grid):
    def __init__(self, node_configs: dict[int, dict]):
        self._run_id = 1
        self.connections, self.processes = {}, {}
        spawn = mp.get_context("spawn")
        try:
            for node_id, config in node_configs.items():
                parent, child = spawn.Pipe()
                process = spawn.Process(target=_worker, args=(child, node_id, config), daemon=True)
                process.start()
                child.close()
                self.connections[node_id], self.processes[node_id] = parent, process
        except Exception:
            self.close()
            raise

    @property
    def run(self):
        from flwr.common import Run
        return Run.create_empty(self._run_id)

    def set_run(self, run_id: int) -> None:
        self._run_id = run_id

    def get_node_ids(self):
        return list(self.connections)

    def create_message(self, content, message_type, dst_node_id, group_id, ttl=None):
        return Message(content, dst_node_id=dst_node_id, message_type=message_type,
                       group_id=group_id, ttl=ttl)

    def push_messages(self, messages):
        raise NotImplementedError("local harness implements synchronous send_and_receive only")

    def pull_messages(self, message_ids):
        raise NotImplementedError("local harness implements synchronous send_and_receive only")

    def send_and_receive(self, messages, *, timeout=None):
        pending = {}
        for message in messages:
            node = message.metadata.dst_node_id
            original = message.metadata
            message = Message(content=message.content, metadata=Metadata(
                run_id=self._run_id, message_id=uuid.uuid4().hex,
                src_node_id=0, dst_node_id=node, reply_to_message_id="",
                group_id=original.group_id, created_at=original.created_at,
                ttl=original.ttl, message_type=original.message_type))
            connection = self.connections[node]
            try:
                connection.send_bytes(serialize(message))
                pending[node] = (connection, message.metadata.message_id)
            except (BrokenPipeError, EOFError, OSError):
                continue
        deadline = time.monotonic() + (30 if timeout is None else timeout)
        from multiprocessing.connection import wait
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready = wait([entry[0] for entry in pending.values()], timeout=remaining)
            if not ready:
                break
            for node, (connection, message_id) in list(pending.items()):
                if connection in ready:
                    try:
                        reply = deserialize(connection.recv_bytes())
                        if reply.metadata.reply_to_message_id != message_id:
                            continue  # Drain stale replies after an earlier timeout.
                        yield reply
                    except (EOFError, OSError):
                        pass
                    del pending[node]

    def close(self):
        for connection in self.connections.values():
            try:
                connection.send_bytes(b"")
            except (OSError, EOFError):
                pass
        for process in self.processes.values():
            process.join(timeout=2)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
        for connection in self.connections.values():
            connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

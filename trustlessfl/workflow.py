"""AION coordinator using the Flower Message/Grid APIs, not FedAvg aggregation."""

import math

from flwr.app import Message
from flwr.serverapp import Grid

from .client_app import payload, records
from .crypto import ProtocolError, verify
from .protocol import Parameters, certificate, check_certificate


class AionWorkflow:
    def __init__(self, p: Parameters, registry: dict, *, timeout: float = 30):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ProtocolError("timeout must be positive and finite")
        self.p, self.registry, self.timeout = p, registry, timeout
        self.nodes: dict[str, int] = {}

    def _send(self, grid: Grid, node_ids: list[int], request: dict) -> list[tuple[int, dict]]:
        messages = [Message(records(request), dst_node_id=n, message_type="query.aion",
                            group_id=self.p.task, ttl=self.timeout) for n in node_ids]
        result = []
        for reply in grid.send_and_receive(messages, timeout=self.timeout):
            if not reply.has_error() and reply.metadata.src_node_id in node_ids:
                try:
                    envelope = payload(reply)
                    verify(envelope, self.registry)
                    result.append((reply.metadata.src_node_id, envelope))
                except (ProtocolError, KeyError, TypeError, ValueError):
                    continue
        return result

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
        if not set(self.p.clients).issubset(self.nodes):
            raise ProtocolError("all fixed-cohort clients must be available")
        if len(set(self.p.aggregators) & self.nodes.keys()) < self.p.quorum:
            raise ProtocolError("insufficient available aggregators")

    def agree(self, votes: list[dict]) -> dict:
        for vote in votes:
            try:
                return certificate(vote["body"], votes, self.p, self.registry)
            except ProtocolError:
                continue
        raise ProtocolError("no aggregator quorum agreed; round aborted")

    def run(self, grid: Grid, rounds: int) -> list[dict]:
        if type(rounds) is not int or rounds < 1:
            raise ProtocolError("rounds must be a positive integer")
        self.discover(grid)
        enrollments = self.call(grid, self.p.clients, "enroll")
        if len(enrollments) != len(self.p.clients):
            raise ProtocolError("incomplete enrollment")
        current = self.agree(self.call(grid, self.p.aggregators, "initialize", enrollments=enrollments))
        history = [current]
        for round_id in range(1, rounds + 1):
            updates = self.call(grid, self.p.clients, "train", model=current)
            if len(updates) != len(self.p.clients):
                raise ProtocolError("fixed-cohort client dropout; start a fresh task")
            roster = self.agree(self.call(grid, self.p.aggregators, "prepare", model=current, updates=updates))
            shares = self.call(grid, self.p.aggregators, "share", roster=roster)
            result = self.agree(self.call(grid, self.p.aggregators, "finalize", roster=roster, shares=shares))
            body = check_certificate(result, self.p, self.registry)
            if body["kind"] != "model" or body["round"] != round_id:
                raise ProtocolError("unexpected model certificate")
            committed = self.call(grid, self.p.aggregators, "commit", model=result)
            from .crypto import digest
            expected = self.p.claim("committed", round_id, model=digest(body))
            if sum(verify(v, self.registry) == expected for v in committed) < self.p.quorum:
                raise ProtocolError("commit quorum unavailable")
            current = result
            history.append(current)
        return history

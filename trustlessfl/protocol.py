"""Signed, fixed-cohort AION-ASR rounds; each node owns only its own state.

Certificates implement quorum safety with abort, not HotStuff view-change.
The coordinator never receives individual VSS shares in plaintext.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import numpy as np

from .crypto import (
    Identity, ORDER, ProtocolError, aggregate_commitments, decrypt_share,
    digest, encrypt_share, reconstruct, split, verify, verify_share,
)
from .numeric import FixedPoint, OUTPUT_MODULUS


@dataclass(frozen=True)
class Parameters:
    task: str
    clients: tuple[str, ...]
    aggregators: tuple[str, ...]
    faults: int = 1
    dimension: int = 3
    decimals: int = 4
    max_abs: float = 100.0
    learning_rate: float = 0.1

    def __post_init__(self):
        if type(self.faults) is not int or type(self.dimension) is not int:
            raise ProtocolError("faults and dimension must be integers")
        if self.faults < 1 or len(self.aggregators) < 3 * self.faults + 1:
            raise ProtocolError("AION requires n >= 3f+1 and f >= 1")
        if len(self.clients) < 2 or self.dimension < 1 or not self.task:
            raise ProtocolError("invalid task or cohort")
        names = self.clients + self.aggregators
        if len(set(names)) != len(names):
            raise ProtocolError("roles must have unique identities")
        if not 0 < self.learning_rate <= 1:
            raise ProtocolError("invalid learning rate")
        self.codec

    @property
    def threshold(self) -> int:
        return self.faults + 1

    @property
    def quorum(self) -> int:
        return len(self.aggregators) - self.faults

    @property
    def codec(self) -> FixedPoint:
        return FixedPoint(self.decimals, self.max_abs, len(self.clients))

    @classmethod
    def from_dict(cls, value: dict) -> Parameters:
        return cls(**{**value, "clients": tuple(value["clients"]),
                      "aggregators": tuple(value["aggregators"])})

    def claim(self, kind: str, round_id: int, **kwargs) -> dict:
        return {"protocol": "aion-asr-research-v1", "task": self.task,
                "kind": kind, "round": round_id, **kwargs}


def certificate(body: dict, votes: list[dict], p: Parameters, registry: dict) -> dict:
    selected = {}
    for vote in votes:
        try:
            claim = verify(vote, registry)
            signer = vote["sender"]
            if signer in p.aggregators and claim == body:
                selected[signer] = vote
        except ProtocolError:
            continue
    if len(selected) < p.quorum:
        raise ProtocolError("insufficient valid, distinct aggregator votes")
    return {"body": body, "votes": [selected[k] for k in sorted(selected)]}


def check_certificate(cert: dict, p: Parameters, registry: dict) -> dict:
    body = cert["body"]
    certificate(body, cert["votes"], p, registry)
    if body.get("task") != p.task or body.get("protocol") != "aion-asr-research-v1":
        raise ProtocolError("certificate belongs to another task")
    return body


def _aad(p: Parameters, sender: str, recipient: str, commitments: list[int]) -> dict:
    return {"task": p.task, "sender": sender, "recipient": recipient,
            "commitments": digest(commitments)}


class Party:
    def __init__(self, identity: Identity, p: Parameters, registry: dict, state: dict | None = None,
                 *, trainer=None):
        self.identity, self.p, self.registry = identity, p, registry
        # Locally provisioned callable, never supplied through server messages.
        self.trainer = trainer
        self.state = state if state is not None else {}
        if registry.get(identity.name) != identity.public():
            raise ProtocolError("identity does not match pinned registry")
        if identity.name not in p.clients + p.aggregators:
            raise ProtocolError("unknown party")

    def _expect(self, envelope: dict, sender: str, kind: str, round_id: int) -> dict:
        body = verify(envelope, self.registry, sender=sender)
        for key, value in self.p.claim(kind, round_id).items():
            if body.get(key) != value:
                raise ProtocolError("wrong protocol, task, phase, or round")
        return body

    def _lock(self, slot: str, value: dict) -> None:
        locks = self.state.setdefault("locks", {})
        hashed = digest(value)
        if slot in locks and locks[slot] != hashed:
            raise ProtocolError("equivocation: conflicting value for a locked slot")
        locks[slot] = hashed

    def hello(self, _request: dict) -> dict:
        return self.identity.sign(self.p.claim("hello", 0))

    def enroll(self, _request: dict) -> dict:
        if self.identity.name not in self.p.clients:
            raise ProtocolError("only clients can enroll")
        if "enrollment" not in self.state:
            secret = secrets.randbelow(ORDER - 1) + 1
            shares, commitments = split(secret, self.p.threshold, len(self.p.aggregators))
            packets = {
                name: encrypt_share(shares[j], self.registry[name]["encryption"],
                                    _aad(self.p, self.identity.name, name, commitments))
                for j, name in enumerate(self.p.aggregators, 1)
            }
            self.state["secret"] = secret
            self.state["enrollment"] = self.identity.sign(self.p.claim(
                "enrollment", 0, commitments=commitments, packets=packets))
        return self.state["enrollment"]

    def initialize(self, request: dict) -> dict:
        if self.identity.name not in self.p.aggregators:
            raise ProtocolError("only aggregators can hold shares")
        enrollments = request["enrollments"]
        if [e["sender"] for e in enrollments] != list(self.p.clients):
            raise ProtocolError("initialization requires the pinned cohort in order")
        shares, commitments = {}, {}
        index = self.p.aggregators.index(self.identity.name) + 1
        for envelope in enrollments:
            name = envelope["sender"]
            body = self._expect(envelope, name, "enrollment", 0)
            com = body["commitments"]
            if len(com) != self.p.threshold:
                raise ProtocolError("wrong VSS degree")
            value = decrypt_share(body["packets"][self.identity.name], self.identity,
                                  _aad(self.p, name, self.identity.name, com))
            if not verify_share(index, value, com):
                raise ProtocolError("invalid client VSS share")
            shares[name], commitments[name] = value, com
        enrollment_hash = digest(enrollments)
        body = self.p.claim("model", 0, model=[0.0] * self.p.dimension,
                            enrollment=enrollment_hash, parent="")
        self._lock("initialization", body)
        self.state.update(shares=shares, commitments=commitments, enrollment=enrollment_hash)
        self.state.setdefault("last_model", body)
        return self.identity.sign(body)

    def train(self, request: dict) -> dict:
        if self.identity.name not in self.p.clients or "secret" not in self.state:
            raise ProtocolError("client not initialized")
        previous = check_certificate(request["model"], self.p, self.registry)
        round_id = previous["round"] + 1
        if previous["kind"] != "model" or round_id < 1:
            raise ProtocolError("expected certified previous model")
        cached = self.state.setdefault("updates", {})
        if str(round_id) in cached:
            result = cached[str(round_id)]
            if result["body"]["parent"] != digest(previous):
                raise ProtocolError("conflicting model on training retry")
            return result
        if round_id != self.state.get("last_round", 0) + 1:
            raise ProtocolError("out-of-order training request")
        weights = np.asarray(previous["model"], dtype=float)
        if weights.shape != (self.p.dimension,) or not np.isfinite(weights).all():
            raise ProtocolError("invalid model")
        partition = self.p.clients.index(self.identity.name)
        if self.trainer is None:
            from .task import local_delta
            delta = local_delta(weights, partition, self.p.learning_rate)
        else:
            delta = self.trainer(weights, partition, self.p.learning_rate, round_id)
        if np.asarray(delta).shape != (self.p.dimension,):
            raise ProtocolError("trainer returned wrong model dimension")
        masked = self.p.codec.mask(delta, self.state["secret"], self.p.task, round_id)
        result = self.identity.sign(self.p.claim("update", round_id,
                                   parent=digest(previous), vector=masked))
        cached[str(round_id)] = result
        self.state["last_round"] = round_id
        return result

    def prepare(self, request: dict) -> dict:
        if "shares" not in self.state:
            raise ProtocolError("aggregator not initialized")
        previous = check_certificate(request["model"], self.p, self.registry)
        if previous != self.state["last_model"]:
            raise ProtocolError("previous model does not match local committed state")
        round_id = previous["round"] + 1
        updates = request["updates"]
        if [e["sender"] for e in updates] != list(self.p.clients):
            raise ProtocolError("fixed-cohort ASR aborts on dropout or membership change")
        for envelope in updates:
            body = self._expect(envelope, envelope["sender"], "update", round_id)
            if body["parent"] != digest(previous):
                raise ProtocolError("update trained on inconsistent model")
            vector = body["vector"]
            if len(vector) != self.p.dimension or any(type(v) is not int or not 0 <= v < OUTPUT_MODULUS for v in vector):
                raise ProtocolError("invalid masked vector")
        claim = self.p.claim("roster", round_id, parent=digest(previous),
                             members=list(self.p.clients), updates=digest(updates))
        self._lock(f"roster/{round_id}", claim)
        self.state["pending"] = {"claim": claim, "updates": updates}
        return self.identity.sign(claim)

    def share(self, request: dict) -> dict:
        roster = check_certificate(request["roster"], self.p, self.registry)
        if roster != self.state.get("pending", {}).get("claim"):
            raise ProtocolError("roster certificate does not match locally verified inputs")
        self._lock(f"release/{roster['round']}", roster)
        value = sum(self.state["shares"].values()) % ORDER
        return self.identity.sign(self.p.claim("aggregate-share", roster["round"],
                                  roster=digest(roster), value=value))

    def finalize(self, request: dict) -> dict:
        roster = check_certificate(request["roster"], self.p, self.registry)
        if roster != self.state.get("pending", {}).get("claim"):
            raise ProtocolError("unexpected finalization roster")
        # Exact retries need not reconstruct sensitive intermediates again.
        proposed = self.state.get("proposed_model")
        if proposed is not None and proposed["round"] == roster["round"]:
            return self.identity.sign(proposed)
        commitments = aggregate_commitments([self.state["commitments"][c] for c in self.p.clients])
        shares = valid_shares(request["shares"], roster, commitments, self.p, self.registry)
        secret = reconstruct(shares, commitments)
        vectors = [u["body"]["vector"] for u in self.state["pending"]["updates"]]
        total = [sum(values) % OUTPUT_MODULUS for values in zip(*vectors, strict=True)]
        decoded = self.p.codec.unmask(total, secret, self.p.task, roster["round"], len(self.p.clients))
        previous = self.state["last_model"]
        model = [w + x / (self.p.codec.scale * len(self.p.clients))
                 for w, x in zip(previous["model"], decoded, strict=True)]
        body = self.p.claim("model", roster["round"], model=model,
                            enrollment=self.state["enrollment"], parent=digest(previous),
                            roster=digest(roster))
        self._lock(f"result/{roster['round']}", body)
        self.state["proposed_model"] = body
        return self.identity.sign(body)

    def commit(self, request: dict) -> dict:
        body = check_certificate(request["model"], self.p, self.registry)
        if body != self.state.get("proposed_model"):
            raise ProtocolError("model differs from independently reconstructed result")
        self.state["last_model"] = body
        return self.identity.sign(self.p.claim("committed", body["round"], model=digest(body)))


def valid_shares(envelopes: list[dict], roster: dict, commitments: list[int],
                 p: Parameters, registry: dict) -> dict[int, int]:
    shares = {}
    for envelope in envelopes:
        try:
            name = envelope["sender"]
            if name not in p.aggregators:
                continue
            body = verify(envelope, registry, sender=name)
            if any(body.get(k) != v for k, v in p.claim("aggregate-share", roster["round"]).items()):
                continue
            if body["roster"] != digest(roster):
                continue
            index = p.aggregators.index(name) + 1
            if verify_share(index, body["value"], commitments):
                shares[index] = body["value"]
        except (ProtocolError, KeyError, TypeError, ValueError):
            continue
    if len(shares) < p.threshold:
        raise ProtocolError("not enough valid aggregate shares")
    return shares

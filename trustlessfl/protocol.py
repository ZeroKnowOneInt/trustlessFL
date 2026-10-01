"""Signed AION-ASR research rounds; each node owns only its own state.

Certificates and optional signed leader rotation are not full HotStuff.
The coordinator never receives individual VSS shares in plaintext.
"""

from __future__ import annotations

import copy
import secrets
from dataclasses import asdict, dataclass

import numpy as np

from .crypto import (
    Identity, ORDER, ProtocolError, aggregate_commitments, canonical, decrypt_share,
    decrypt_pedersen_share, decrypt_pedersen_vector_shares, digest,
    encrypt_pedersen_vector_shares, encrypt_share,
    pedersen_split, pedersen_verify_share, reconstruct,
    split, sum_pedersen_shares, verify, verify_share,
    _lagrange_at_zero,
)
from .numeric import FixedPoint, HPRF_MODULUS_192, MGFIntegerCodec
from .mgf_wire import (check_mgf_aggregate_mask, evolve_mgf_state,
                       evolve_artifact_state, initial_mgf_state, validate_mgf_state)
from .mgf_selection import (admission_bound, artifact_selection_bound, check_probe,
                           check_update_probe, select_probes)


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
    privacy_groups: tuple[tuple[str, ...], ...] = ()
    ema_weight: float = 0.0
    mask_backend: str = "artifact"
    hprf_width: int = 8
    hprf_input_bits: int | None = None
    leader_views: bool = False
    hotstuff: bool = False
    mgf_beta: str = ""
    mgf_initial_alpha: str = ""
    mgf_initial_bound: str = ""
    mgf_initial_term: str = ""
    oracle_mgf: bool = False
    mgf_projection: tuple[int, int] = ()
    mgf_single_view: bool = False
    mgf_percentile: bool = False
    mgf_artifact_bound: bool = False
    mgf_mask_sum_norm: bool = False
    original_hprf_setup: tuple[int, ...] = ()

    def __post_init__(self):
        if isinstance(self.original_hprf_setup, list):
            object.__setattr__(self, "original_hprf_setup", tuple(self.original_hprf_setup))
        if self.mask_backend == "aion-original":
            if len(self.clients) * 100000 >= ORDER:
                raise ProtocolError("original seed sum could wrap the VSS field")
        if type(self.faults) is not int or type(self.dimension) is not int:
            raise ProtocolError("faults and dimension must be integers")
        if self.faults < 1 or len(self.aggregators) < 3 * self.faults + 1:
            raise ProtocolError("AION requires n >= 3f+1 and f >= 1")
        if len(self.clients) < 2 or self.dimension < 1 or not self.task:
            raise ProtocolError("invalid task or cohort")
        names = self.clients + self.aggregators
        if len(set(names)) != len(names):
            raise ProtocolError("roles must have unique identities")
        if self.privacy_groups:
            flattened = tuple(name for group in self.privacy_groups for name in group)
            if (any(len(group) < 2 for group in self.privacy_groups)
                    or set(flattened) != set(self.clients) or len(flattened) != len(self.clients)):
                raise ProtocolError("privacy groups must partition clients into groups of at least two")
        if not 0 < self.learning_rate <= 1:
            raise ProtocolError("invalid learning rate")
        if not 0 <= self.ema_weight < 1 or (self.ema_weight and not self.privacy_groups):
            raise ProtocolError("EMA requires precommitted privacy groups and weight in (0, 1)")
        if type(self.leader_views) is not bool:
            raise ProtocolError("leader_views must be boolean")
        if type(self.hotstuff) is not bool or (self.hotstuff and self.leader_views):
            raise ProtocolError("HotStuff and legacy leader views are distinct consensus modes")
        if type(self.oracle_mgf) is not bool or (self.oracle_mgf and (
                self.dimension != 61706 or self.privacy_groups or self.ema_weight or self.mgf_beta)):
            raise ProtocolError("plaintext classifier oracle is FMNIST-only and separate from secure MGF")
        if self.mask_backend == "lwe-192-reference" and len(self.clients) * HPRF_MODULUS_192 >= ORDER:
            raise ProtocolError("HPRF key sum could wrap the VSS field")
        self.codec
        if type(self.mgf_percentile) is not bool or (self.mgf_percentile and not self.mgf_projection):
            raise ProtocolError("percentile MGF requires a masked projection")
        if type(self.mgf_artifact_bound) is not bool or (self.mgf_artifact_bound and not self.mgf_percentile):
            raise ProtocolError("artifact MGF bound requires percentile projection")
        if (type(self.mgf_mask_sum_norm) is not bool or
                (self.mgf_mask_sum_norm and (not self.mgf_beta or self.mgf_artifact_bound))):
            raise ProtocolError("selected mask-sum norm requires non-artifact bounded MGF")
        if not isinstance(self.mgf_projection, tuple):
            raise ProtocolError("MGF projection must be a tuple")
        if type(self.mgf_single_view) is not bool or (self.mgf_single_view and not self.mgf_projection):
            raise ProtocolError("single-view MGF requires a projection")
        if self.mgf_projection and (not self.mgf_beta or len(self.mgf_projection) != 2
                or any(type(v) is not int for v in self.mgf_projection)
                or not 0 <= self.mgf_projection[0] < self.mgf_projection[1] <= self.dimension):
            raise ProtocolError("invalid bounded MGF projection")
        if self.mgf_beta:
            if self.privacy_groups or self.ema_weight:
                raise ProtocolError("MGF per-round key mode is incompatible with legacy group/EMA mode")
            initial_mgf_state(self)
        elif any((self.mgf_initial_alpha, self.mgf_initial_bound, self.mgf_initial_term)):
            raise ProtocolError("incomplete MGF configuration")

    @property
    def threshold(self) -> int:
        return self.faults + 1

    @property
    def quorum(self) -> int:
        return len(self.aggregators) - self.faults

    def leader(self, view: int) -> str:
        if type(view) is not int or view < 0:
            raise ProtocolError("invalid consensus view")
        return self.aggregators[view % len(self.aggregators)]

    @property
    def codec(self) -> FixedPoint:
        return FixedPoint(self.decimals, self.max_abs, len(self.clients),
                          self.mask_backend, self.hprf_width, self.hprf_input_bits,
                          self.original_hprf_setup)

    @property
    def scalar_mask(self) -> bool:
        return self.mask_backend in ("artifact", "aion-original")

    @property
    def mgf_enabled(self) -> bool:
        return bool(self.mgf_beta)

    @property
    def mgf_dimension(self) -> int:
        return self.mgf_projection[1] - self.mgf_projection[0] if self.mgf_projection else self.dimension

    @property
    def mgf_slice(self) -> slice:
        return slice(*self.mgf_projection) if self.mgf_projection else slice(None)

    @property
    def mgf_codec(self) -> MGFIntegerCodec:
        if not self.mgf_enabled:
            raise ProtocolError("MGF is not enabled")
        return MGFIntegerCodec(self.decimals, self.max_abs, len(self.clients),
                               str(self.max_abs), self.codec.output_modulus)

    @property
    def groups(self) -> tuple[tuple[str, ...], ...]:
        return self.privacy_groups or (self.clients,)

    def allowed_members(self, members: tuple[str, ...]) -> bool:
        chosen = set(members)
        if self.mgf_enabled or self.oracle_mgf:
            # A fresh mask key is generated for each round, so revealing this
            # round's aggregate key cannot be differenced against a prior one.
            return (len(members) >= 2 and tuple(c for c in self.clients if c in chosen) == members)
        return (bool(chosen) and tuple(c for c in self.clients if c in chosen) == members
                and all(not chosen.intersection(group) or set(group) <= chosen for group in self.groups))

    @property
    def config_digest(self) -> str:
        """Preserve existing non-HotStuff task commitments across this opt-in."""
        value = asdict(self)
        if not self.mgf_mask_sum_norm:
            value.pop("mgf_mask_sum_norm")
        if not self.original_hprf_setup:
            value.pop("original_hprf_setup")
        if not self.hotstuff:
            value.pop("hotstuff")
        resolved_input_bits = self.codec.effective_hprf_input_bits
        if resolved_input_bits == 32:
            value.pop("hprf_input_bits")
        else:
            value["hprf_input_bits"] = resolved_input_bits
        if not self.mgf_enabled:
            for name in ("mgf_beta", "mgf_initial_alpha", "mgf_initial_bound", "mgf_initial_term"):
                value.pop(name)
        if not self.oracle_mgf:
            value.pop("oracle_mgf")
        if not self.mgf_projection:
            value.pop("mgf_projection")
        if not self.mgf_single_view:
            value.pop("mgf_single_view")
        if not self.mgf_percentile:
            value.pop("mgf_percentile")
        if not self.mgf_artifact_bound:
            value.pop("mgf_artifact_bound")
        return digest(value)

    @classmethod
    def from_dict(cls, value: dict) -> Parameters:
        return cls(**{**value, "clients": tuple(value["clients"]),
                      "aggregators": tuple(value["aggregators"]),
                      "mgf_projection": tuple(value.get("mgf_projection", ())),
                      "privacy_groups": tuple(tuple(g) for g in value.get("privacy_groups", ()))})

    def claim(self, kind: str, round_id: int, **kwargs) -> dict:
        return {"protocol": "aion-asr-research-v2", "task": self.task,
                "config": self.config_digest,
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
    if (body.get("task") != p.task or body.get("protocol") != "aion-asr-research-v2"
            or body.get("config") != p.config_digest):
        raise ProtocolError("certificate belongs to another task")
    if p.leader_views and body.get("kind") in ("roster", "model") and body.get("round", 0) > 0:
        _check_leader_evidence(cert.get("consensus"), body, p, registry)
    if p.hotstuff and body.get("kind") in ("roster", "model") and body.get("round", 0) > 0:
        from .hotstuff import check_decision
        check_decision(p, registry, body, cert.get("hotstuff"))
    return body


def _check_leader_evidence(evidence: dict, body: dict, p: Parameters, registry: dict) -> None:
    if not isinstance(evidence, dict):
        raise ProtocolError("missing leader/view evidence")
    view = evidence.get("view")
    if type(view) is not int or not 0 <= view < len(p.aggregators):
        raise ProtocolError("invalid leader view")
    phase = "roster" if body["kind"] == "roster" else "model"
    context = body["parent"] if phase == "roster" else body["roster"]
    proposal = evidence.get("proposal")
    if (not isinstance(proposal, dict) or proposal.get("sender") != p.leader(view)
            or verify(proposal, registry, sender=p.leader(view)) != body):
        raise ProtocolError("invalid leader proposal")
    _check_view_chain(evidence, body["round"], phase, context, p, registry)


def _check_view_chain(evidence: dict, round_id: int, phase: str, context: str,
                      p: Parameters, registry: dict) -> None:
    view = evidence["view"]
    previous = evidence.get("previous_views", [])
    if not isinstance(previous, list) or len(previous) != max(view - 1, 0):
        raise ProtocolError("incomplete view-change certificate chain")
    chain = previous + ([evidence.get("view_qc")] if view else [])
    if not view and evidence.get("view_qc") is not None:
        raise ProtocolError("unexpected view-change evidence for view zero")
    for number, qc in enumerate(chain, start=1):
        expected = p.claim("view-change", round_id, phase=phase, view=number, context=context)
        if not isinstance(qc, dict) or qc.get("body") != expected:
            raise ProtocolError("missing view-change quorum certificate")
        certificate(expected, qc.get("votes", []), p, registry)


def check_finalized_model(cert: dict, p: Parameters, registry: dict) -> dict:
    """Require a second, model-bound quorum before clients train on a result.

    The genesis model is certified by initialization votes. Subsequent models
    need both reconstruction votes and durable commit acknowledgements.
    """
    body = check_certificate(cert, p, registry)
    if body.get("kind") != "model" or type(body.get("round")) is not int or body["round"] < 0:
        raise ProtocolError("expected certified model")
    ancestry = body.get("ancestry")
    if ancestry is not None and (not isinstance(ancestry, list)
            or len(ancestry) != body["round"]
            or any(not isinstance(value, str) or len(value) != 64
                   or any(character not in "0123456789abcdef" for character in value)
                   for value in ancestry)
            or (body["round"] > 0 and ancestry[-1] != body.get("parent"))):
        raise ProtocolError("invalid signed model ancestry")
    if p.mgf_enabled:
        validate_mgf_state(p, body.get("mgf_state"))
        if body["round"] == 0 and body["mgf_state"] != initial_mgf_state(p):
            raise ProtocolError("genesis MGF state differs from committed setup")
    elif "mgf_state" in body:
        raise ProtocolError("unexpected MGF state in non-MGF model")
    if body["round"]:
        if p.leader_views:
            _check_model_roster_proof(cert, body, p, registry)
        expected = p.claim("committed", body["round"], model=digest(body))
        commits = cert.get("commits")
        if not isinstance(commits, dict) or commits.get("body") != expected:
            raise ProtocolError("missing or mismatched model commit certificate")
        certificate(expected, commits.get("votes", []), p, registry)
    return body


def _check_model_roster_proof(cert: dict, body: dict, p: Parameters, registry: dict) -> None:
    roster_cert = cert.get("roster_certificate")
    if not isinstance(roster_cert, dict):
        raise ProtocolError("model lacks committed roster proof")
    roster = check_finalized_roster(roster_cert, p, registry)
    if roster["round"] != body["round"] or digest(roster) != body.get("roster"):
        raise ProtocolError("model roster proof differs from result")


def check_finalized_roster(cert: dict, p: Parameters, registry: dict) -> dict:
    """In leader-view mode, release shares only after roster commit quorum."""
    body = check_certificate(cert, p, registry)
    if body.get("kind") != "roster" or type(body.get("round")) is not int or body["round"] < 1:
        raise ProtocolError("expected certified roster")
    if p.leader_views:
        expected = p.claim("roster-committed", body["round"], roster=digest(body))
        commits = cert.get("commits")
        if not isinstance(commits, dict) or commits.get("body") != expected:
            raise ProtocolError("missing or mismatched roster commit certificate")
        certificate(expected, commits.get("votes", []), p, registry)
    return body


def _aad(p: Parameters, sender: str, recipient: str, commitments: list[int]) -> dict:
    return {"task": p.task, "sender": sender, "recipient": recipient,
            "commitments": digest(commitments)}


def _mgf_key_aad(p: Parameters, sender: str, recipient: str, round_id: int,
                 commitments, coordinate: int) -> dict:
    return {"protocol": "aion-mgf-ephemeral-key-v1", "task": p.task,
            "sender": sender, "recipient": recipient, "round": round_id,
            "coordinate": coordinate, "commitments": digest(commitments)}


def _mgf_new_key(p: Parameters):
    if p.mask_backend == "aion-original":
        return secrets.randbelow(100000) + 1
    if p.mask_backend == "artifact":
        return secrets.randbelow(ORDER - 1) + 1
    modulus = HPRF_MODULUS_192 if p.mask_backend == "lwe-192-reference" else ORDER
    return [secrets.randbelow(modulus) for _ in range(p.hprf_width)]


def _oracle_key_material(p: Parameters, identity: Identity, registry: dict,
                         key, round_id: int) -> dict:
    """Recipient-bound per-round ASR key shares without expensive mask VSS."""
    count = len(p.aggregators)
    if p.scalar_mask:
        shares, commitments = split(key, p.threshold, count)
        packets = {name: encrypt_share(
            shares[index], registry[name]["encryption"],
            _mgf_key_aad(p, identity.name, name, round_id, commitments, 0))
            for index, name in enumerate(p.aggregators, 1)}
    else:
        components = [split(value, p.threshold, count) for value in key]
        commitments = [com for _, com in components]
        packets = {name: [encrypt_share(
            shares[index], registry[name]["encryption"],
            _mgf_key_aad(p, identity.name, name, round_id, commitments, coordinate))
            for coordinate, (shares, _) in enumerate(components)]
            for index, name in enumerate(p.aggregators, 1)}
    return {"commitments": commitments, "packets": packets}


def _oracle_local_key(p: Parameters, identity: Identity, sender: str,
                      material: dict, round_id: int):
    if (not isinstance(material, dict) or set(material) != {"commitments", "packets"}
            or not isinstance(material["packets"], dict)
            or set(material["packets"]) != set(p.aggregators)):
        raise ProtocolError("invalid oracle ASR key material")
    commitments = material["commitments"]
    packets = material["packets"][identity.name]
    index = p.aggregators.index(identity.name) + 1
    if p.scalar_mask:
        if not isinstance(commitments, list) or len(commitments) != p.threshold:
            raise ProtocolError("invalid oracle ASR key commitments")
        share = decrypt_share(packets, identity, _mgf_key_aad(
            p, sender, identity.name, round_id, commitments, 0))
        if not verify_share(index, share, commitments):
            raise ProtocolError("invalid oracle ASR key share")
        return share
    if (not isinstance(commitments, list) or len(commitments) != p.hprf_width
            or not isinstance(packets, list) or len(packets) != p.hprf_width):
        raise ProtocolError("invalid oracle vector key material")
    result = []
    for coordinate, (com, packet) in enumerate(zip(commitments, packets, strict=True)):
        if not isinstance(com, list) or len(com) != p.threshold:
            raise ProtocolError("invalid oracle vector key commitments")
        share = decrypt_share(packet, identity, _mgf_key_aad(
            p, sender, identity.name, round_id, commitments, coordinate))
        if not verify_share(index, share, com):
            raise ProtocolError("invalid oracle vector key share")
        result.append(share)
    return result


def _mgf_update_material(p: Parameters, identity: Identity, registry: dict,
                         key, masks: list[int], round_id: int, alpha: str) -> dict:
    """Per-round ASR key and exact-mask shares, encrypted for each holder."""
    count = len(p.aggregators)
    if p.scalar_mask:
        key_shares, key_commitments = split(key, p.threshold, count)
        key_packets = {name: encrypt_share(
            key_shares[index], registry[name]["encryption"],
            _mgf_key_aad(p, identity.name, name, round_id, key_commitments, 0))
            for index, name in enumerate(p.aggregators, 1)}
    else:
        components = [split(value, p.threshold, count) for value in key]
        key_commitments = [commitments for _, commitments in components]
        key_packets = {name: [encrypt_share(
            shares[index], registry[name]["encryption"],
            _mgf_key_aad(p, identity.name, name, round_id, key_commitments, coordinate))
            for coordinate, (shares, _) in enumerate(components)]
            for index, name in enumerate(p.aggregators, 1)}
    components = [pedersen_split(mask, p.threshold, count) for mask in masks]
    mask_commitments = [commitments for _, commitments in components]
    mask_packets = {name: encrypt_pedersen_vector_shares(
        [shares[index] for shares, _ in components], registry[name]["encryption"], task=p.task,
        sender=identity.name, recipient=name, round_id=round_id,
        commitments=mask_commitments)
        for index, name in enumerate(p.aggregators, 1)}
    return {"alpha": alpha, "key_commitments": key_commitments,
            "key_packets": key_packets, "mask_commitments": mask_commitments,
            "mask_packets": mask_packets}


def _mgf_local_material(p: Parameters, identity: Identity, sender: str,
                        material: dict, round_id: int):
    """Verify both recipient-bound share families before voting for a roster."""
    if (not isinstance(material, dict) or set(material) != {
            "alpha", "key_commitments", "key_packets", "mask_commitments", "mask_packets"}
            or not isinstance(material["key_packets"], dict)
            or not isinstance(material["mask_packets"], dict)
            or set(material["key_packets"]) != set(p.aggregators)
            or set(material["mask_packets"]) != set(p.aggregators)):
        raise ProtocolError("invalid MGF update share material")
    index = p.aggregators.index(identity.name) + 1
    commitments = material["key_commitments"]
    packets = material["key_packets"][identity.name]
    if p.scalar_mask:
        if not isinstance(commitments, list) or len(commitments) != p.threshold:
            raise ProtocolError("invalid MGF key commitments")
        key_share = decrypt_share(packets, identity,
                                  _mgf_key_aad(p, sender, identity.name, round_id,
                                               commitments, 0))
        if not verify_share(index, key_share, commitments):
            raise ProtocolError("invalid MGF key share")
    else:
        if (not isinstance(commitments, list) or len(commitments) != p.hprf_width
                or not isinstance(packets, list) or len(packets) != p.hprf_width):
            raise ProtocolError("invalid MGF vector key material")
        key_share = []
        for coordinate, (com, packet) in enumerate(zip(commitments, packets, strict=True)):
            if not isinstance(com, list) or len(com) != p.threshold:
                raise ProtocolError("invalid MGF vector key commitments")
            part = decrypt_share(packet, identity, _mgf_key_aad(
                p, sender, identity.name, round_id, commitments, coordinate))
            if not verify_share(index, part, com):
                raise ProtocolError("invalid MGF vector key share")
            key_share.append(part)
    mask_commitments = material["mask_commitments"]
    mask_packets = material["mask_packets"][identity.name]
    if not isinstance(mask_commitments, list) or len(mask_commitments) != p.mgf_dimension:
        raise ProtocolError("invalid MGF mask material")
    if isinstance(mask_packets, dict):
        pairs = decrypt_pedersen_vector_shares(mask_packets, identity, task=p.task,
                                               sender=sender, round_id=round_id,
                                               commitments=mask_commitments)
    elif isinstance(mask_packets, list) and len(mask_packets) == p.mgf_dimension:
        # Retain the original coordinate packets when replaying old signed updates.
        pairs = [decrypt_pedersen_share(packet, identity, task=p.task, sender=sender,
                                        round_id=round_id, coordinate=coordinate,
                                        commitments=com)
                 for coordinate, (com, packet) in enumerate(zip(mask_commitments, mask_packets, strict=True))]
    else:
        raise ProtocolError("invalid MGF mask material")
    mask_shares = []
    for com, pair in zip(mask_commitments, pairs, strict=True):
        if not isinstance(com, list) or len(com) != p.threshold:
            raise ProtocolError("invalid MGF mask commitments")
        if not pedersen_verify_share(index, pair, com):
            raise ProtocolError("invalid MGF mask share")
        mask_shares.append(list(pair))
    return key_share, mask_shares


def _sum_key_shares(shares: dict, members: list[str], p: Parameters):
    if p.scalar_mask:
        return sum(shares[c] for c in members) % ORDER
    return [sum(shares[c][k] for c in members) % ORDER for k in range(p.hprf_width)]


def _sum_key_commitments(commitments: dict, members: list[str], p: Parameters):
    if p.scalar_mask:
        return aggregate_commitments([commitments[c] for c in members])
    return [aggregate_commitments([commitments[c][k] for c in members])
            for k in range(p.hprf_width)]


def _reconstruct_key(shares: dict, commitments, p: Parameters):
    if p.scalar_mask:
        return reconstruct(shares, commitments)
    modulus = HPRF_MODULUS_192 if p.mask_backend == "lwe-192-reference" else ORDER
    return [reconstruct({i: value[k] for i, value in shares.items()}, commitments[k]) % modulus
            for k in range(p.hprf_width)]


class Party:
    def __init__(self, identity: Identity, p: Parameters, registry: dict, state: dict | None = None,
                 *, trainer=None):
        self.identity, self.p, self.registry = identity, p, registry
        # Locally provisioned callable, never supplied through server messages.
        self.trainer = trainer
        self._consensus_preview = False
        self.state = state if state is not None else {}
        if registry.get(identity.name) != identity.public():
            raise ProtocolError("identity does not match pinned registry")
        if identity.name not in p.clients + p.aggregators:
            raise ProtocolError("unknown party")

    def _expect(self, envelope: dict, sender: str, kind: str, round_id: int) -> dict:
        body = verify(envelope, self.registry, sender=sender)
        if not isinstance(body, dict):
            raise ProtocolError("invalid signed protocol body")
        for key, value in self.p.claim(kind, round_id).items():
            if body.get(key) != value:
                raise ProtocolError("wrong protocol, task, phase, or round")
        return body

    def _lock(self, slot: str, value: dict) -> None:
        if self._consensus_preview:
            return
        locks = self.state.setdefault("locks", {})
        hashed = digest(value)
        if slot in locks and locks[slot] != hashed:
            raise ProtocolError("equivocation: conflicting value for a locked slot")
        locks[slot] = hashed

    def view_vote(self, request: dict) -> dict:
        """Sign a round/phase-bound request to leave a stalled leader view."""
        if not self.p.leader_views or self.identity.name not in self.p.aggregators:
            raise ProtocolError("leader views not enabled for this party")
        phase, round_id, view = request["phase"], request["round"], request["view"]
        if phase not in ("roster", "model") or type(view) is not int or not 1 <= view < len(self.p.aggregators):
            raise ProtocolError("invalid view-change request")
        if phase == "roster":
            prior = self.state.get("last_model")
            if prior is None or round_id != prior["round"] + 1:
                raise ProtocolError("wrong roster view-change round")
            context = digest(prior)
        else:
            pending = self.state.get("pending", {}).get("claim")
            if pending is None or round_id != pending["round"]:
                raise ProtocolError("wrong model view-change round")
            context = digest(pending)
        if request.get("context") != context:
            raise ProtocolError("view-change context mismatch")
        previous = request.get("previous_views", [])
        if not isinstance(previous, list) or len(previous) != view - 1:
            raise ProtocolError("incomplete prior view-change certificate chain")
        for number, qc in enumerate(previous, start=1):
            expected = self.p.claim("view-change", round_id, phase=phase,
                                    view=number, context=context)
            if not isinstance(qc, dict) or qc.get("body") != expected:
                raise ProtocolError("invalid prior view-change certificate")
            certificate(expected, qc.get("votes", []), self.p, self.registry)
        claim = self.p.claim("view-change", round_id, phase=phase, view=view, context=context)
        self._lock(f"view-vote/{phase}/{round_id}/{view}", claim)
        return self.identity.sign(claim)

    def _check_local_view(self, request: dict, body: dict, phase: str, context: str) -> None:
        if self.p.hotstuff:
            if not self._consensus_preview:
                from .hotstuff import check_decision
                check_decision(self.p, self.registry, body, request.get("hotstuff"))
            return
        if not self.p.leader_views:
            return
        evidence = request.get("consensus")
        if not isinstance(evidence, dict):
            raise ProtocolError("missing leader consensus request")
        view = evidence.get("view")
        if type(view) is not int or not 0 <= view < len(self.p.aggregators):
            raise ProtocolError("invalid leader view")
        _check_view_chain(evidence, body["round"], phase, context, self.p, self.registry)
        proposal = evidence.get("proposal")
        if proposal is None:
            if self.identity.name != self.p.leader(view):
                raise ProtocolError("only the view leader may propose")
        elif (not isinstance(proposal, dict) or proposal.get("sender") != self.p.leader(view)
              or verify(proposal, self.registry, sender=self.p.leader(view)) != body):
            raise ProtocolError("leader proposal differs from independently verified value")

    def hotstuff_candidate(self, request: dict) -> dict:
        """Validate a candidate without acquiring an irreversible AION lock."""
        from .hotstuff import candidate_claim
        if not self.p.hotstuff or self.identity.name not in self.p.aggregators:
            raise ProtocolError("HotStuff candidate requires enabled aggregator")
        command = request.get("command")
        if not isinstance(command, dict) or command.get("action") not in ("prepare", "finalize"):
            raise ProtocolError("invalid HotStuff application command")
        if command["action"] == "prepare" and "staged" in command:
            resolver = getattr(self, "_resolve_staged", None)
            if resolver is None:
                raise ProtocolError("staged HotStuff candidate has no local update resolver")
            preview_command = resolver(command)
        else:
            preview_command = command
        # prepare/finalize replace top-level preview fields and only read nested
        # committed data. Avoid copying prior round's large masked updates and
        # HotStuff proposal cache for every independent candidate validation.
        preview = Party(self.identity, self.p, self.registry, self.state.copy())
        preview._consensus_preview = True
        candidate = getattr(preview, command["action"])(preview_command)["body"]
        return self.identity.sign(candidate_claim(self.p, candidate))

    def hotstuff(self, request: dict) -> dict:
        """Persist HotStuff state in the same transaction as AION state."""
        from .hotstuff import HotStuffSlot, check_slot
        if not self.p.hotstuff or self.identity.name not in self.p.aggregators:
            raise ProtocolError("HotStuff requires enabled aggregator")
        slot = request.get("slot")
        check_slot(slot)
        key = digest(slot)
        slots = self.state.setdefault("hotstuff_slots", {})
        if key not in slots:
            if slot["phase"] == "roster":
                parent = self.state.get("last_model")
                expected_round = parent["round"] + 1 if parent else None
            else:
                parent = self.state.get("pending", {}).get("claim")
                expected_round = parent["round"] if parent else None
            if (parent is None or slot["round"] != expected_round
                    or slot["context"] != digest(parent)):
                raise ProtocolError("HotStuff slot does not extend local application state")

        def validate(value, command):
            from .hotstuff import candidate_claim
            envelope = self.hotstuff_candidate({"command": command})
            if envelope["body"] != candidate_claim(self.p, value):
                raise ProtocolError("HotStuff value differs from independently validated command")

        engine = HotStuffSlot(self.identity, self.p, self.registry, slot,
                             slots.setdefault(key, {}), validate, reuse_validation=True)
        op = request.get("op")
        if op == "status":
            return engine.status()
        if op == "recover":
            return engine.recover()
        if op == "new_view":
            return engine.new_view(request["view"], request.get("timeout_qc"))
        if op == "timeout":
            return engine.timeout(request["view"])
        if op == "propose":
            return engine.propose(request["view"], request["messages"],
                                  request["value"], request["command"])
        if op == "prepare":
            return engine.prepare(request["proposal"])
        if op == "precommit":
            return engine.precommit(request["proposal"], request["prepare_qc"])
        if op == "commit":
            return engine.commit(request["proposal"], request["prepare_qc"], request["precommit_qc"])
        if op == "decide":
            value, command = request["value"], request["command"]
            engine.decide(value, command, request["commit_qc"])
            if command["action"] == "prepare" and "staged" in command:
                resolver = getattr(self, "_resolve_staged", None)
                if resolver is None:
                    raise ProtocolError("staged HotStuff decision has no local update resolver")
                command = resolver(command)
            return getattr(self, command["action"])({**command, "hotstuff": request["commit_qc"]})
        raise ProtocolError("unknown HotStuff operation")

    def hello(self, _request: dict) -> dict:
        return self.identity.sign(self.p.claim("hello", 0))

    def enroll(self, _request: dict) -> dict:
        if self.identity.name not in self.p.clients:
            raise ProtocolError("only clients can enroll")
        if "enrollment" not in self.state:
            if self.p.mgf_enabled or self.p.oracle_mgf:
                # MGF rotates its ASR key in each signed update. Keeping a
                # long-lived unused key would add secret state and permit
                # cross-round key-sum differencing if accidentally released.
                commitments, packets = [], {}
            elif self.p.scalar_mask:
                secret = (secrets.randbelow(100000) + 1 if self.p.mask_backend == "aion-original"
                          else secrets.randbelow(ORDER - 1) + 1)
                shares, commitments = split(secret, self.p.threshold, len(self.p.aggregators))
                packets = {
                    name: encrypt_share(shares[j], self.registry[name]["encryption"],
                                        _aad(self.p, self.identity.name, name, commitments))
                    for j, name in enumerate(self.p.aggregators, 1)
                }
            else:
                modulus = HPRF_MODULUS_192 if self.p.mask_backend == "lwe-192-reference" else ORDER
                secret = [secrets.randbelow(modulus) for _ in range(self.p.hprf_width)]
                components = [split(value, self.p.threshold, len(self.p.aggregators))
                              for value in secret]
                commitments = [com for _, com in components]
                packets = {
                    name: [encrypt_share(shares[j], self.registry[name]["encryption"],
                                         {**_aad(self.p, self.identity.name, name, commitments),
                                          "coordinate": k})
                           for k, (shares, _) in enumerate(components)]
                    for j, name in enumerate(self.p.aggregators, 1)
                }
            if not self.p.mgf_enabled and not self.p.oracle_mgf:
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
            if self.p.mgf_enabled or self.p.oracle_mgf:
                if com != [] or body.get("packets") != {}:
                    raise ProtocolError("dynamic ASR enrollment must not publish a persistent key")
                value = None
            elif self.p.scalar_mask:
                if len(com) != self.p.threshold:
                    raise ProtocolError("wrong VSS degree")
                value = decrypt_share(body["packets"][self.identity.name], self.identity,
                                      _aad(self.p, name, self.identity.name, com))
                if not verify_share(index, value, com):
                    raise ProtocolError("invalid client VSS share")
            else:
                packets = body["packets"][self.identity.name]
                if (not isinstance(com, list) or len(com) != self.p.hprf_width
                        or not isinstance(packets, list) or len(packets) != self.p.hprf_width):
                    raise ProtocolError("wrong vector VSS width")
                value = []
                for k, (coordinate, packet) in enumerate(zip(com, packets, strict=True)):
                    if not isinstance(coordinate, list) or len(coordinate) != self.p.threshold:
                        raise ProtocolError("wrong vector VSS degree")
                    part = decrypt_share(packet, self.identity,
                                         {**_aad(self.p, name, self.identity.name, com),
                                          "coordinate": k})
                    if not verify_share(index, part, coordinate):
                        raise ProtocolError("invalid vector VSS share")
                    value.append(part)
            shares[name], commitments[name] = value, com
        enrollment_hash = digest(enrollments)
        body = self.p.claim("model", 0, model=[0.0] * self.p.dimension,
                            enrollment=enrollment_hash, parent="", ancestry=[],
                            **({"mgf_state": initial_mgf_state(self.p)}
                               if self.p.mgf_enabled else {}))
        self._lock("initialization", body)
        self.state.update(shares=shares, commitments=commitments, enrollment=enrollment_hash)
        self.state.setdefault("last_model", body)
        return self.identity.sign(body)

    def genesis_vote(self, _request: dict) -> dict:
        """Read-only reissue of an already locked genesis vote."""
        if self.identity.name not in self.p.aggregators:
            raise ProtocolError("only aggregators can report genesis votes")
        body = self.state.get("last_model")
        if (not isinstance(body, dict) or body.get("kind") != "model" or body.get("round") != 0
                or self.state.get("locks", {}).get("initialization") != digest(body)):
            raise ProtocolError("no durable genesis vote")
        return self.identity.sign(body)

    def model_status(self, _request: dict) -> dict:
        """Report the local committed model body without releasing a secret."""
        if self.identity.name not in self.p.aggregators:
            raise ProtocolError("only aggregators can report model status")
        body = self.state.get("last_model")
        if not isinstance(body, dict) or body.get("kind") != "model":
            raise ProtocolError("no local committed model")
        return self.identity.sign(self.p.claim("model-status", body["round"], model=body))

    def train(self, request: dict) -> dict:
        if (self.identity.name not in self.p.clients or "enrollment" not in self.state
                or (not self.p.mgf_enabled and not self.p.oracle_mgf
                    and "secret" not in self.state)):
            raise ProtocolError("client not initialized")
        previous = check_finalized_model(request["model"], self.p, self.registry)
        round_id = previous["round"] + 1
        if previous["kind"] != "model" or round_id < 1:
            raise ProtocolError("expected certified previous model")
        cached = self.state.setdefault("updates", {})
        if str(round_id) in cached:
            result = cached[str(round_id)]
            if result["body"]["parent"] != digest(previous):
                raise ProtocolError("conflicting model on training retry")
            return result
        last_round = self.state.get("last_round", 0)
        if round_id <= last_round:
            raise ProtocolError("out-of-order training request")
        if round_id == last_round + 1 and round_id > 1:
            trained_on_hash = self.state.get("trained_on_hash")
            if trained_on_hash is None or previous.get("parent") != trained_on_hash:
                raise ProtocolError("certified model does not extend the client's training history")
        elif round_id > last_round + 1:
            ancestry = previous.get("ancestry")
            compact_catch_up = (isinstance(ancestry, list) and len(ancestry) == previous["round"]
                                and (last_round == 0 or
                                     ancestry[last_round - 1] == self.state.get("trained_on_hash")))
            if not compact_catch_up:
                history = request.get("history")
                if not isinstance(history, list) or len(history) != round_id:
                    raise ProtocolError("missing certified catch-up history")
                prior = None
                for index, cert in enumerate(history):
                    ancestor = check_finalized_model(cert, self.p, self.registry)
                    if ancestor["round"] != index or (prior is not None and ancestor.get("parent") != digest(prior)):
                        raise ProtocolError("invalid certified catch-up history")
                    if index == last_round - 1 and digest(ancestor) != self.state.get("trained_on_hash"):
                        raise ProtocolError("catch-up history diverges from prior training")
                    prior = ancestor
                if prior != previous:
                    raise ProtocolError("catch-up history does not reach requested model")
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
        if self.p.mgf_enabled:
            mgf_state = validate_mgf_state(self.p, previous.get("mgf_state"))
            key = _mgf_new_key(self.p)
            hprf_output = self.p.codec._mask(key, self.p.task, round_id, self.p.dimension)
            projected, masks = self.p.mgf_codec.mask(np.asarray(delta)[self.p.mgf_slice],
                                                       hprf_output[self.p.mgf_slice], mgf_state["alpha"])
            if self.p.mgf_projection:
                encoded = self.p.codec.encode(delta)
                modulus = self.p.codec.output_modulus
                masked = [(x * self.p.codec.padding + h) % modulus
                          for x, h in zip(encoded, hprf_output, strict=True)]
                if self.p.mgf_single_view:
                    masked[self.p.mgf_slice] = [0] * self.p.mgf_dimension
            else:
                masked = projected
            material = _mgf_update_material(self.p, self.identity, self.registry,
                                            key, masks, round_id, mgf_state["alpha"])
            body = self.p.claim("update", round_id,
                                        parent=digest(previous), vector=masked,
                                        mgf=material,
                                        **({"mgf_vector": projected} if self.p.mgf_projection else {}))
            if self.p.mgf_percentile:
                body["mgf_probe"] = self.identity.sign(self.p.claim("mgf-probe", round_id,
                    parent=digest(previous), vector=projected, update=digest(body),
                    key_material={"commitments": material["key_commitments"],
                                  "packets": material["key_packets"]}))
            result = self.identity.sign(body)
        else:
            oracle_probe = {}
            if self.p.oracle_mgf:
                from .fmnist_artifact_mgf import CLASSIFIER_WEIGHT
                key = _mgf_new_key(self.p)
                oracle_probe["oracle_key"] = _oracle_key_material(
                    self.p, self.identity, self.registry, key, round_id)
                oracle_probe["oracle_classifier"] = np.asarray(
                    delta, dtype=np.float32)[CLASSIFIER_WEIGHT].astype(float).tolist()
            else:
                key = self.state["secret"]
            masked = self.p.codec.mask(delta, key, self.p.task, round_id)
            result = self.identity.sign(self.p.claim("update", round_id,
                                        parent=digest(previous), vector=masked, **oracle_probe))
        cached[str(round_id)] = result
        self.state["trained_on_hash"] = digest(previous)
        self.state["last_round"] = round_id
        return result

    def prepare(self, request: dict) -> dict:
        if "shares" not in self.state:
            raise ProtocolError("aggregator not initialized")
        previous = check_finalized_model(request["model"], self.p, self.registry)
        if previous != self.state["last_model"]:
            raise ProtocolError("previous model does not match local committed state")
        round_id = previous["round"] + 1
        updates = request["updates"]
        members = tuple(e["sender"] for e in updates)
        if not self.p.allowed_members(members):
            raise ProtocolError("dropout or membership change: ASR requires complete precommitted privacy groups")
        mgf_key_shares, mgf_mask_shares, oracle_key_shares = {}, {}, {}
        mgf_state = (validate_mgf_state(self.p, previous.get("mgf_state"))
                     if self.p.mgf_enabled else None)
        selection = None
        if self.p.mgf_percentile:
            candidates = request.get("mgf_candidates")
            bound = (artifact_selection_bound(self.p, self.registry, mgf_state,
                     request.get("mgf_cohort_norm"), candidates, digest(previous), round_id)
                     if self.p.mgf_artifact_bound else mgf_state["bound"])
            chosen, selection = select_probes(self.p, self.registry, candidates,
                digest(previous), round_id, bound)
            if self.p.mgf_artifact_bound:
                selection["cohort_mask_linf"] = request["mgf_cohort_norm"]["body"]["mask_linf"]
                selection["cohort_norm_certificate"] = request["mgf_cohort_norm"]
            if list(members) != chosen:
                raise ProtocolError("roster differs from masked MGF percentile selection")
            by_client = {probe["sender"]: probe for probe in candidates}
            if any(update["body"].get("mgf_probe") != by_client[update["sender"]] for update in updates):
                raise ProtocolError("selected update differs from candidate probe")
        for envelope in updates:
            if self.p.mgf_enabled:
                _, key_share, mask_shares = self._validate_mgf_update(
                    envelope, previous, mgf_state)
                mgf_key_shares[envelope["sender"]] = key_share
                mgf_mask_shares[envelope["sender"]] = mask_shares
            else:
                body = self._expect(envelope, envelope["sender"], "update", round_id)
                if body["parent"] != digest(previous):
                    raise ProtocolError("update trained on inconsistent model")
                vector = body["vector"]
                modulus = self.p.codec.output_modulus
                if (not isinstance(vector, list) or len(vector) != self.p.dimension
                        or any(type(v) is not int or not 0 <= v < modulus for v in vector)):
                    raise ProtocolError("invalid masked vector")
                if self.p.oracle_mgf:
                    projection = np.asarray(body.get("oracle_classifier"), dtype=float)
                    if projection.shape != (840,) or not np.isfinite(projection).all():
                        raise ProtocolError("invalid plaintext classifier oracle")
                    oracle_key_shares[envelope["sender"]] = _oracle_local_key(
                        self.p, self.identity, envelope["sender"],
                        body.get("oracle_key"), round_id)
        late = request.get("late")
        if late is not None:
            late_body = check_certificate(late, self.p, self.registry)
            if (not self.p.ema_weight or late_body != self.state.get("proposed_late")
                    or late_body.get("round") != round_id - 1):
                raise ProtocolError("invalid or unverified late aggregate")
        claim = self.p.claim("roster", round_id, parent=digest(previous),
                             members=list(members), updates=digest(updates),
                             late=digest(late["body"]) if late is not None else "",
                             **({"mgf_candidates": digest(candidates), "mgf_selection": selection}
                                if self.p.mgf_percentile else {}))
        self._check_local_view(request, claim, "roster", digest(previous))
        self._lock(f"roster/{round_id}", claim)
        self.state["pending"] = {"claim": claim, "updates": updates,
                                 "late": late["body"] if late is not None else None}
        if self.p.mgf_enabled:
            self.state["pending"]["mgf_key_shares"] = mgf_key_shares
            self.state["pending"]["mgf_mask_shares"] = mgf_mask_shares
        if self.p.oracle_mgf:
            self.state["pending"]["oracle_key_shares"] = oracle_key_shares
        if self.p.hotstuff and not self._consensus_preview:
            self.state["pending_hotstuff"] = request["hotstuff"]
        if self.p.leader_views and request["consensus"].get("proposal") is not None:
            self.state["pending_consensus"] = request["consensus"]
        return self.identity.sign(claim)

    def _validate_mgf_update(self, envelope: dict, previous: dict, state: dict):
        """Validate one signed bounded update and this recipient's encrypted shares."""
        if not self.p.mgf_enabled or self.identity.name not in self.p.aggregators:
            raise ProtocolError("MGF admission requires an aggregator")
        if not isinstance(envelope, dict) or envelope.get("sender") not in self.p.clients:
            raise ProtocolError("invalid MGF update author")
        envelope = copy.deepcopy(envelope)
        round_id = previous["round"] + 1
        body = self._expect(envelope, envelope["sender"], "update", round_id)
        if body.get("parent") != digest(previous):
            raise ProtocolError("update trained on inconsistent model")
        vector = body.get("vector")
        if (not isinstance(vector, list) or len(vector) != self.p.dimension
                or any(type(v) is not int for v in vector)):
            raise ProtocolError("invalid MGF update vector")
        probe = body.get("mgf_vector") if self.p.mgf_projection else vector
        modulus = self.p.codec.output_modulus
        if (not isinstance(probe, list) or len(probe) != self.p.mgf_dimension
                or not self.p.mgf_codec.accepts(probe, admission_bound(self.p, state))
                or (self.p.mgf_projection and any(not 0 <= v < modulus for v in vector))):
            raise ProtocolError("MGF rejected masked vector")
        if self.p.mgf_percentile:
            check_update_probe(self.p, self.registry, body)
        if self.p.mgf_single_view and any(vector[self.p.mgf_slice]):
            raise ProtocolError("single-view MGF forbids duplicate masked coordinates")
        material = body.get("mgf")
        if not isinstance(material, dict) or material.get("alpha") != state["alpha"]:
            raise ProtocolError("MGF update alpha differs from certified model")
        key_share, mask_shares = self._validated_mgf_material(
            envelope, material, round_id, digest(previous))
        return body, key_share, mask_shares

    def _validated_mgf_material(self, envelope: dict, material: dict,
                                round_id: int, parent: str):
        """Reuse only this recipient's signed, exact-input local validation.

        ClientApp instances are transient: the bounded cache lives in the same
        recipient-private state as its VSS shares, not in a global worker cache
        or the coordinator. A cache miss always performs full decryption/VSS
        verification. Its proof is never accepted as a remote admission vote.
        """
        update_hash = digest(envelope)
        cache = self.state.get("mgf_local_material")
        if cache is not None and (not isinstance(cache, dict)
                                  or not isinstance(cache.get("entries"), list)
                                  or len(cache["entries"]) > 32
                                  or any(not isinstance(entry, dict) or "update" not in entry
                                         for entry in cache["entries"])):
            raise ProtocolError("invalid local MGF material cache")
        if cache is None or cache.get("round") != round_id or cache.get("parent") != parent:
            cache = {"round": round_id, "parent": parent, "entries": []}
            if not self._consensus_preview:
                self.state["mgf_local_material"] = cache
        for entry in cache["entries"]:
            if entry["update"] != update_hash:
                continue
            try:
                values = entry["values"]
                expected = self.p.claim("mgf-local-material", round_id, parent=parent,
                                        update=update_hash, values=digest(values))
                if (self._expect(entry["proof"], self.identity.name,
                                 "mgf-local-material", round_id) != expected
                        or not isinstance(values, dict) or set(values) != {"key", "mask"}
                        or not isinstance(values["mask"], list)
                        or len(values["mask"]) != self.p.mgf_dimension):
                    raise ProtocolError("invalid local MGF material cache")
                return copy.deepcopy(values["key"]), copy.deepcopy(values["mask"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ProtocolError("invalid local MGF material cache") from exc
        key_share, mask_shares = _mgf_local_material(
            self.p, self.identity, envelope["sender"], material, round_id)
        values = {"key": key_share, "mask": mask_shares}
        # Skip huge full-dimension material; at most 32 entries of <=2 MiB.
        # No cache stores a client's full key or another recipient's share.
        if (not self._consensus_preview and len(cache["entries"]) < 32
                and len(canonical(values)) <= 2 * 1024 * 1024):
            proof = self.identity.sign(self.p.claim("mgf-local-material", round_id,
                parent=parent, update=update_hash, values=digest(values)))
            cache["entries"].append({"update": update_hash,
                                      "values": copy.deepcopy(values), "proof": proof})
        return key_share, mask_shares

    def mgf_admit(self, request: dict) -> dict:
        """Admission vote plus recipient-local validation cache; no roster lock."""
        if not self.p.mgf_enabled or self.identity.name not in self.p.aggregators:
            raise ProtocolError("MGF admission is not enabled for this aggregator")
        previous = check_finalized_model(request.get("model"), self.p, self.registry)
        if previous != self.state.get("last_model"):
            raise ProtocolError("MGF admission needs the local committed model")
        state = validate_mgf_state(self.p, previous.get("mgf_state"))
        update = request.get("update")
        self._validate_mgf_update(update, previous, state)
        return self.identity.sign(self.p.claim(
            "mgf-admit", previous["round"] + 1, parent=digest(previous),
            update=digest(update)))

    def _mgf_cohort_context(self, request: dict):
        """Pin one candidate cohort before privately reconstructing its key sum."""
        if not self.p.mgf_percentile or self.identity.name not in self.p.aggregators:
            raise ProtocolError("cohort mask norm requires percentile MGF aggregators")
        previous = check_finalized_model(request["model"], self.p, self.registry)
        if previous != self.state.get("last_model"):
            raise ProtocolError("cohort mask norm does not extend committed model")
        probes = request.get("mgf_candidates")
        round_id, parent = previous["round"] + 1, digest(previous)
        # Reuse signature, numeric, duplicate, and canonical-order checks.
        select_probes(self.p, self.registry, probes, parent, round_id,
                      previous["mgf_state"]["bound"])
        # Avoid a one-client complement when both full and selected key sums
        # become known to aggregators in very small smoke-test cohorts.
        if len(probes) != 2 and len(probes) < 10:
            raise ProtocolError("cohort norm requires two or at least ten candidates")
        materials = {probe["sender"]: check_probe(self.p, self.registry, probe,
                     parent, round_id).get("key_material") for probe in probes}
        if any(material is None for material in materials.values()):
            raise ProtocolError("cohort mask norm lacks signed key material")
        context = self.p.claim("mgf-cohort-context", round_id, parent=parent,
                               candidates=digest(probes))
        locked = self.state.get("mgf_cohort_locks", {}).get(str(round_id))
        if locked is not None and locked != digest(context):
            raise ProtocolError("conflicting MGF candidate cohort")
        return previous, context, materials

    def mgf_cohort_vote(self, request: dict) -> dict:
        """Lock a quorum-approved cohort before any aggregate share release."""
        _, context, materials = self._mgf_cohort_context(request)
        for name, material in materials.items():
            _oracle_local_key(self.p, self.identity, name, material, context["round"])
        self.state.setdefault("mgf_cohort_locks", {})[str(context["round"])] = digest(context)
        return self.identity.sign(context)

    def _mgf_require_cohort_certificate(self, request: dict, context: dict):
        proof = request.get("cohort_certificate")
        if not isinstance(proof, dict):
            raise ProtocolError("missing MGF cohort approval certificate")
        if check_certificate(proof, self.p, self.registry) != context:
            raise ProtocolError("MGF cohort approval differs from candidate context")

    def mgf_cohort_share(self, request: dict) -> dict:
        """Relay encrypted aggregate shares, never plaintext shares to Flower."""
        _, context, materials = self._mgf_cohort_context(request)
        self._mgf_require_cohort_certificate(request, context)
        local = {name: _oracle_local_key(self.p, self.identity, name, material,
                  context["round"]) for name, material in materials.items()}
        value = _sum_key_shares(local, list(materials), self.p)
        values = [value] if self.p.scalar_mask else value
        packets = {name: [encrypt_share(part, self.registry[name]["encryption"],
                    {**context, "sender": self.identity.name, "recipient": name,
                     "coordinate": coordinate}) for coordinate, part in enumerate(values)]
                   for name in self.p.aggregators}
        self.state.setdefault("mgf_cohort_locks", {})[str(context["round"])] = digest(context)
        return self.identity.sign(self.p.claim("mgf-cohort-share", context["round"],
            context=digest(context), packets=packets))

    def mgf_cohort_norm(self, request: dict) -> dict:
        """Reconstruct inside each aggregator and publish only the mask norm."""
        from fractions import Fraction
        from .mgf_wire import _decimal
        previous, context, materials = self._mgf_cohort_context(request)
        self._mgf_require_cohort_certificate(request, context)
        commitments = _sum_key_commitments(
            {name: material["commitments"] for name, material in materials.items()},
            list(materials), self.p)
        shares = {}
        envelopes = request.get("cohort_shares")
        if not isinstance(envelopes, list):
            raise ProtocolError("missing encrypted cohort shares")
        for envelope in envelopes:
            try:
                sender = envelope["sender"]
                if sender not in self.p.aggregators:
                    continue
                body = self._expect(envelope, sender, "mgf-cohort-share", context["round"])
                if body.get("context") != digest(context):
                    continue
                packets = body["packets"][self.identity.name]
                width = 1 if self.p.scalar_mask else self.p.hprf_width
                if not isinstance(packets, list) or len(packets) != width:
                    continue
                parts = [decrypt_share(packet, self.identity, {**context, "sender": sender,
                         "recipient": self.identity.name, "coordinate": coordinate})
                         for coordinate, packet in enumerate(packets)]
                index = self.p.aggregators.index(sender) + 1
                coms = [commitments] if self.p.scalar_mask else commitments
                if not all(verify_share(index, part, com)
                           for part, com in zip(parts, coms, strict=True)):
                    continue
                shares[index] = parts[0] if self.p.scalar_mask else parts
            except (ProtocolError, KeyError, TypeError, ValueError):
                continue
        if len(shares) < self.p.threshold:
            raise ProtocolError("insufficient valid encrypted cohort shares")
        secret = _reconstruct_key(shares, commitments, self.p)
        mask = self.p.codec._mask(secret, self.p.task, context["round"],
                                  self.p.dimension)[self.p.mgf_slice]
        norm = Fraction(previous["mgf_state"]["alpha"]) * max(mask) / self.p.codec.output_modulus
        norm_text = _decimal(norm) if norm else "0"
        self.state.setdefault("mgf_cohort_locks", {})[str(context["round"])] = digest(context)
        return self.identity.sign(self.p.claim("mgf-cohort-norm", context["round"],
            parent=context["parent"], candidates=context["candidates"], mask_linf=norm_text))

    def roster_vote(self, request: dict) -> dict:
        """Read-only vote for a roster this aggregator already verified."""
        if self.identity.name not in self.p.aggregators:
            raise ProtocolError("only aggregators can report roster votes")
        body = self.state.get("pending", {}).get("claim")
        if (not isinstance(body, dict) or body.get("kind") != "roster"
                or self.state.get("locks", {}).get(f"roster/{body.get('round')}") != digest(body)):
            raise ProtocolError("no durable roster proposal")
        if request.get("candidate") != digest(body):
            raise ProtocolError("peer roster differs from local proposal")
        return self.identity.sign(body)

    def roster_proof(self, _request: dict) -> dict:
        """Local handoff of a locked roster and its leader evidence."""
        if self.identity.name not in self.p.aggregators:
            raise ProtocolError("only aggregators can report roster votes")
        body = self.state.get("pending", {}).get("claim")
        if (not isinstance(body, dict) or body.get("kind") != "roster"
                or self.state.get("locks", {}).get(f"roster/{body.get('round')}") != digest(body)):
            raise ProtocolError("no durable roster proposal")
        consensus = self.state.get("pending_consensus") if self.p.leader_views else None
        if self.p.leader_views and not isinstance(consensus, dict):
            raise ProtocolError("durable roster lacks leader evidence")
        return self.identity.sign(self.p.claim(
            "roster-proof", body["round"], candidate=body,
            vote=self.identity.sign(body), consensus=consensus,
            **({"hotstuff": self.state.get("pending_hotstuff")} if self.p.hotstuff else {})))

    def late_prepare(self, request: dict) -> dict:
        """Certify a full omitted privacy group from the immediately preceding round."""
        if not self.p.ema_weight or "shares" not in self.state:
            raise ProtocolError("EMA not enabled")
        current = check_finalized_model(request["current"], self.p, self.registry)
        previous = check_finalized_model(request["previous"], self.p, self.registry)
        stale_round = current["round"]
        if (stale_round < 1 or current != self.state["last_model"]
                or previous["round"] != stale_round - 1 or current["parent"] != digest(previous)):
            raise ProtocolError("late update is not from the preceding committed round")
        updates = request["updates"]
        members = tuple(e["sender"] for e in updates)
        committed = set(self.state.get("committed_members", {}).get(str(stale_round), []))
        if not self.p.allowed_members(members) or committed.intersection(members):
            raise ProtocolError("late roster overlaps a released key or splits a privacy group")
        for envelope in updates:
            body = self._expect(envelope, envelope["sender"], "update", stale_round)
            if body.get("parent") != digest(previous):
                raise ProtocolError("late update trained on wrong model")
            vector = body.get("vector")
            modulus = self.p.codec.output_modulus
            if (not isinstance(vector, list) or len(vector) != self.p.dimension
                    or any(type(v) is not int or not 0 <= v < modulus for v in vector)):
                raise ProtocolError("invalid late masked vector")
        claim = self.p.claim("late-roster", stale_round, current=digest(current),
                             parent=digest(previous), members=list(members), updates=digest(updates))
        self._lock(f"late-roster/{stale_round}", claim)
        self.state["late_pending"] = {"claim": claim, "updates": updates}
        return self.identity.sign(claim)

    def late_share(self, request: dict) -> dict:
        roster = check_certificate(request["roster"], self.p, self.registry)
        if roster != self.state.get("late_pending", {}).get("claim"):
            raise ProtocolError("late roster certificate not locally verified")
        self._lock(f"late-release/{roster['round']}", roster)
        value = _sum_key_shares(self.state["shares"], roster["members"], self.p)
        return self.identity.sign(self.p.claim("late-aggregate-share", roster["round"],
                                               roster=digest(roster), value=value))

    def late_finalize(self, request: dict) -> dict:
        roster = check_certificate(request["roster"], self.p, self.registry)
        if roster != self.state.get("late_pending", {}).get("claim"):
            raise ProtocolError("unexpected late finalization roster")
        proposed = self.state.get("proposed_late")
        if proposed is not None and proposed["round"] == roster["round"]:
            return self.identity.sign(proposed)
        members = roster["members"]
        commitments = _sum_key_commitments(self.state["commitments"], members, self.p)
        shares = valid_shares(request["shares"], roster, commitments, self.p, self.registry,
                              kind="late-aggregate-share")
        secret = _reconstruct_key(shares, commitments, self.p)
        vectors = [u["body"]["vector"] for u in self.state["late_pending"]["updates"]]
        modulus = self.p.codec.output_modulus
        total = [sum(values) % modulus for values in zip(*vectors, strict=True)]
        decoded = self.p.codec.unmask(total, secret, self.p.task, roster["round"], len(members))
        body = self.p.claim("late-delta", roster["round"], current=roster["current"],
                            members=members, vector=decoded, roster=digest(roster))
        self._lock(f"late-result/{roster['round']}", body)
        self.state["proposed_late"] = body
        return self.identity.sign(body)

    def roster_commit(self, request: dict) -> dict:
        if not self.p.leader_views or self.identity.name not in self.p.aggregators:
            raise ProtocolError("roster commit requires leader-view aggregator")
        roster = check_certificate(request["roster"], self.p, self.registry)
        if roster.get("kind") != "roster" or roster != self.state.get("pending", {}).get("claim"):
            raise ProtocolError("roster differs from independently verified pending roster")
        claim = self.p.claim("roster-committed", roster["round"], roster=digest(roster))
        self._lock(f"roster-commit/{roster['round']}", claim)
        return self.identity.sign(claim)

    def share(self, request: dict) -> dict:
        roster = check_finalized_roster(request["roster"], self.p, self.registry)
        if roster != self.state.get("pending", {}).get("claim"):
            raise ProtocolError("roster certificate does not match locally verified inputs")
        self._lock(f"release/{roster['round']}", roster)
        self.state["pending_roster_certificate"] = request["roster"]
        if self.p.mgf_enabled:
            pending = self.state["pending"]
            key_value = _sum_key_shares(pending["mgf_key_shares"], roster["members"], self.p)
            mask_value = [list(sum_pedersen_shares(
                [pending["mgf_mask_shares"][client][coordinate]
                 for client in roster["members"]]))
                for coordinate in range(self.p.mgf_dimension)]
            return self.identity.sign(self.p.claim(
                "mgf-aggregate-share", roster["round"], roster=digest(roster),
                value={"key": key_value, "mask": mask_value}))
        source = (self.state["pending"]["oracle_key_shares"] if self.p.oracle_mgf
                  else self.state["shares"])
        value = _sum_key_shares(source, roster["members"], self.p)
        return self.identity.sign(self.p.claim("aggregate-share", roster["round"],
                                  roster=digest(roster), value=value))

    def finalize(self, request: dict) -> dict:
        roster = check_finalized_roster(request["roster"], self.p, self.registry)
        if roster != self.state.get("pending", {}).get("claim"):
            raise ProtocolError("unexpected finalization roster")
        # Exact retries need not reconstruct sensitive intermediates again.
        proposed = self.state.get("proposed_model")
        if proposed is not None and proposed["round"] == roster["round"]:
            self._check_local_view(request, proposed, "model", digest(roster))
            if self.p.hotstuff and not self._consensus_preview:
                self.state["proposed_hotstuff"] = request["hotstuff"]
            if self.p.leader_views and request["consensus"].get("proposal") is not None:
                self.state["proposed_consensus"] = request["consensus"]
            return self.identity.sign(proposed)
        members = roster["members"]
        vectors = [u["body"]["vector"] for u in self.state["pending"]["updates"]]
        if self.p.mgf_enabled:
            key_commitments, mask_commitments = _mgf_aggregate_commitments(
                self.state["pending"]["updates"], self.p)
            key_shares, aggregate_mask = valid_mgf_shares(
                request["shares"], roster, key_commitments, mask_commitments,
                self.p, self.registry, reconstruct_masks=True)
            secret = _reconstruct_key(key_shares, key_commitments, self.p)
            total = [sum(values) for values in zip(*vectors, strict=True)]
            previous_state = validate_mgf_state(self.p, self.state["last_model"].get("mgf_state"))
            aggregate_hprf = self.p.codec._mask(
                secret, self.p.task, roster["round"], self.p.dimension)[self.p.mgf_slice]
            check_mgf_aggregate_mask(aggregate_mask, aggregate_hprf,
                                     previous_state["alpha"], len(members),
                                     self.p.mgf_codec.scale, modulus=self.p.codec.output_modulus)
            if self.p.mgf_projection:
                modulus = self.p.codec.output_modulus
                modular_total = [value % modulus for value in total]
                if self.p.mgf_single_view:
                    # Projection coordinates have only the bounded view.
                    # Neutralize them before decoding the other coordinates.
                    modular_total[self.p.mgf_slice] = aggregate_hprf
                decoded = self.p.codec.unmask(modular_total,
                                               secret, self.p.task, roster["round"], len(members))
                probes = [u["body"]["mgf_vector"] for u in self.state["pending"]["updates"]]
                probe_total = [sum(values) for values in zip(*probes, strict=True)]
                recovered_probe = self.p.mgf_codec.recover(probe_total, aggregate_mask, len(members),
                                                           alpha=previous_state["alpha"])
                if self.p.mgf_single_view:
                    decoded[self.p.mgf_slice] = recovered_probe
                elif recovered_probe != decoded[self.p.mgf_slice]:
                    raise ProtocolError("MGF projection differs from ASR aggregate")
            else:
                decoded = self.p.mgf_codec.recover(total, aggregate_mask, len(members),
                                                   alpha=previous_state["alpha"])
            next_mgf_state = (evolve_artifact_state(self.p, previous_state,
                decoded[self.p.mgf_slice], len(members), roster["mgf_selection"])
                if self.p.mgf_artifact_bound else evolve_mgf_state(
                self.p, previous_state, decoded[self.p.mgf_slice], len(members), aggregate_hprf,
                aggregate_mask=aggregate_mask if self.p.mgf_mask_sum_norm else None))
        else:
            if self.p.oracle_mgf:
                materials = [update["body"]["oracle_key"]["commitments"]
                             for update in self.state["pending"]["updates"]]
                if self.p.scalar_mask:
                    commitments = aggregate_commitments(materials)
                else:
                    commitments = [aggregate_commitments([com[i] for com in materials])
                                   for i in range(self.p.hprf_width)]
            else:
                commitments = _sum_key_commitments(self.state["commitments"], members, self.p)
            shares = valid_shares(request["shares"], roster, commitments, self.p, self.registry)
            secret = _reconstruct_key(shares, commitments, self.p)
            modulus = self.p.codec.output_modulus
            total = [sum(values) % modulus for values in zip(*vectors, strict=True)]
            decoded = self.p.codec.unmask(total, secret, self.p.task, roster["round"], len(members))
        previous = self.state["last_model"]
        model = [w + x / (self.p.codec.scale * len(members))
                 for w, x in zip(previous["model"], decoded, strict=True)]
        late = self.state["pending"].get("late")
        if late is not None:
            model = [w + self.p.ema_weight * x / (self.p.codec.scale * len(late["members"]))
                     for w, x in zip(model, late["vector"], strict=True)]
        body = self.p.claim("model", roster["round"], model=model,
                            enrollment=self.state["enrollment"], parent=digest(previous),
                            roster=digest(roster),
                            **({"ancestry": [*previous["ancestry"], digest(previous)]}
                               if "ancestry" in previous else {}),
                            **({"mgf_state": next_mgf_state} if self.p.mgf_enabled else {}))
        self._check_local_view(request, body, "model", digest(roster))
        self._lock(f"result/{roster['round']}", body)
        self.state["proposed_model"] = body
        if self.p.hotstuff and not self._consensus_preview:
            self.state["proposed_hotstuff"] = request["hotstuff"]
        if self.p.leader_views and request["consensus"].get("proposal") is not None:
            self.state["proposed_consensus"] = request["consensus"]
        return self.identity.sign(body)

    def proposal_vote(self, request: dict) -> dict:
        """Read-only vote for a value this aggregator already durably proposed."""
        if self.identity.name not in self.p.aggregators:
            raise ProtocolError("only aggregators can report proposed models")
        body = self.state.get("proposed_model")
        if (not isinstance(body, dict) or body.get("kind") != "model"
                or self.state.get("locks", {}).get(f"result/{body.get('round')}") != digest(body)):
            raise ProtocolError("no durable model proposal")
        if request.get("candidate") != digest(body):
            raise ProtocolError("peer candidate differs from local proposal")
        return self.identity.sign(body)

    def proposal_proof(self, _request: dict) -> dict:
        """Local read-only handoff of a proposal and its leader/roster evidence."""
        if self.identity.name not in self.p.aggregators:
            raise ProtocolError("only aggregators can report proposed models")
        body = self.state.get("proposed_model")
        if (not isinstance(body, dict) or body.get("kind") != "model"
                or self.state.get("locks", {}).get(f"result/{body.get('round')}") != digest(body)):
            raise ProtocolError("no durable model proposal")
        roster_cert = self.state.get("pending_roster_certificate")
        if not isinstance(roster_cert, dict) or digest(check_finalized_roster(
                roster_cert, self.p, self.registry)) != body.get("roster"):
            raise ProtocolError("durable proposal lacks certified roster")
        consensus = self.state.get("proposed_consensus") if self.p.leader_views else None
        if self.p.leader_views and not isinstance(consensus, dict):
            raise ProtocolError("durable proposal lacks leader evidence")
        return self.identity.sign(self.p.claim(
            "proposal-proof", body["round"], candidate=body,
            vote=self.identity.sign(body), roster_certificate=roster_cert,
            consensus=consensus,
            **({"hotstuff": self.state.get("proposed_hotstuff")} if self.p.hotstuff else {})))

    def commit(self, request: dict) -> dict:
        body = check_certificate(request["model"], self.p, self.registry)
        if self.p.leader_views:
            _check_model_roster_proof(request["model"], body, self.p, self.registry)
        if body != self.state.get("proposed_model"):
            raise ProtocolError("model differs from independently reconstructed result")
        claim = self.p.claim("committed", body["round"], model=digest(body))
        self._lock(f"model-commit/{body['round']}", claim)
        # A local vote does not prove that the quorum certificate exists. In
        # every mode the durable model pointer advances only on decide().
        self.state["committed_candidate"] = body
        return self.identity.sign(claim)

    def decide(self, request: dict) -> dict:
        if self.identity.name not in self.p.aggregators:
            raise ProtocolError("model decision requires aggregator")
        body = check_finalized_model(request["model"], self.p, self.registry)
        if (body != self.state.get("committed_candidate")
                or body != self.state.get("proposed_model")):
            raise ProtocolError("decision differs from locally prepared model")
        previous = self.state.get("last_model")
        if previous == body:
            return self.identity.sign(self.p.claim("decided", body["round"], model=digest(body)))
        if previous is None or body["round"] != previous["round"] + 1 or body["parent"] != digest(previous):
            raise ProtocolError("decision does not extend local committed chain")
        if "ancestry" in previous and body.get("ancestry") != [*previous["ancestry"], digest(previous)]:
            raise ProtocolError("decision ancestry does not extend local committed chain")
        self._lock(f"model-decision/{body['round']}", body)
        self.state["last_model"] = body
        self.state.pop("mgf_local_material", None)
        self.state.setdefault("committed_members", {})[str(body["round"])] = self.state["pending"]["claim"]["members"]
        # The certified model, roster claim, and durable locks suffice for
        # recovery after a decision. Keeping every signed masked vector in
        # persistent state would grow a paper-scale FMNIST run by hundreds of
        # megabytes per aggregator and make the next round reload it all.
        for key in ("updates", "mgf_key_shares", "mgf_mask_shares", "oracle_key_shares"):
            self.state["pending"].pop(key, None)
        return self.identity.sign(self.p.claim("decided", body["round"], model=digest(body)))


def _mgf_aggregate_commitments(updates: list[dict], p: Parameters):
    materials = [update["body"]["mgf"] for update in updates]
    if p.scalar_mask:
        key_commitments = aggregate_commitments(
            [material["key_commitments"] for material in materials])
    else:
        key_commitments = [aggregate_commitments(
            [material["key_commitments"][coordinate] for material in materials])
            for coordinate in range(p.hprf_width)]
    mask_commitments = [aggregate_commitments(
        [material["mask_commitments"][coordinate] for material in materials])
        for coordinate in range(p.mgf_dimension)]
    return key_commitments, mask_commitments


def valid_mgf_shares(envelopes: list[dict], roster: dict, key_commitments,
                     mask_commitments, p: Parameters, registry: dict, *,
                     reconstruct_masks: bool = False) -> tuple[dict, dict | list[int]]:
    """Validate both VSS families; optionally reconstruct in this validation scope.

    Reconstruction never accepts caller-marked 'verified' shares. All envelope
    signatures, roster bindings, and every Pedersen coordinate are checked here
    before interpolation. Only public interpolation weights are cached.
    """
    if reconstruct_masks and (not isinstance(mask_commitments, list)
                              or len(mask_commitments) != p.mgf_dimension
                              or any(not isinstance(com, list) or len(com) != p.threshold
                                     for com in mask_commitments)):
        raise ProtocolError("invalid MGF reconstruction commitments")
    keys, masks = {}, {}
    for envelope in envelopes:
        try:
            name = envelope["sender"]
            if name not in p.aggregators:
                continue
            # Own a snapshot so caller-owned lists cannot change between
            # signature verification, share checks and interpolation.
            body = verify(copy.deepcopy(envelope), registry, sender=name)
            expected = p.claim("mgf-aggregate-share", roster["round"])
            if (any(body.get(key) != value for key, value in expected.items())
                    or body.get("roster") != digest(roster)):
                continue
            value = body["value"]
            if not isinstance(value, dict) or set(value) != {"key", "mask"}:
                continue
            index = p.aggregators.index(name) + 1
            key_share, mask_shares = value["key"], value["mask"]
            if p.scalar_mask:
                key_valid = verify_share(index, key_share, key_commitments)
            else:
                key_valid = (isinstance(key_share, list) and len(key_share) == p.hprf_width
                             and all(verify_share(index, part, com)
                                     for part, com in zip(key_share, key_commitments, strict=True)))
            mask_valid = (isinstance(mask_shares, list) and len(mask_shares) == p.mgf_dimension
                          and all(pedersen_verify_share(index, pair, commitments)
                                  for pair, commitments in zip(
                                      mask_shares, mask_commitments, strict=True)))
            if key_valid and mask_valid:
                keys[index], masks[index] = key_share, mask_shares
        except (ProtocolError, KeyError, TypeError, ValueError):
            continue
    if len(keys) < p.threshold:
        raise ProtocolError("not enough valid MGF aggregate shares")
    if reconstruct_masks:
        selected = tuple(sorted(masks)[:p.threshold])
        coefficients = _lagrange_at_zero(selected)
        aggregate_mask = [sum(coefficient * masks[index][coordinate][0]
                              for index, coefficient in zip(selected, coefficients, strict=True)) % ORDER
                          for coordinate in range(p.mgf_dimension)]
        return keys, aggregate_mask
    return keys, masks


def valid_shares(envelopes: list[dict], roster: dict, commitments,
                 p: Parameters, registry: dict, *, kind: str = "aggregate-share") -> dict:
    shares = {}
    for envelope in envelopes:
        try:
            name = envelope["sender"]
            if name not in p.aggregators:
                continue
            body = verify(envelope, registry, sender=name)
            if any(body.get(k) != v for k, v in p.claim(kind, roster["round"]).items()):
                continue
            if body["roster"] != digest(roster):
                continue
            index = p.aggregators.index(name) + 1
            value = body["value"]
            if p.scalar_mask:
                valid = verify_share(index, value, commitments)
            else:
                valid = (isinstance(value, list) and len(value) == p.hprf_width
                         and all(verify_share(index, part, com)
                                 for part, com in zip(value, commitments, strict=True)))
            if valid:
                shares[index] = value
        except (ProtocolError, KeyError, TypeError, ValueError):
            continue
    if len(shares) < p.threshold:
        raise ProtocolError("not enough valid aggregate shares")
    return shares

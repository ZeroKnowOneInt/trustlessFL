"""Transport adapter for the author's ASR normal-path computations.

Selected methods are executed from a read-only, hash-pinned author snapshot,
not rewritten into the bounded-MGF protocol. No pickle arrives over Flower.
The source BFT callback is exposed as an event, NOT treated as a commit proof.
"""

import ast
import hashlib
import json
import os
import random
import re
import time
from functools import lru_cache
from pathlib import Path
from types import MethodType, SimpleNamespace

import gmpy2
import numpy as np
from flwr.app import ConfigRecord

from .aion_original_hprf import OriginalAionHPRF
from .crypto import ProtocolError, canonical, digest
from .numeric import FixedPoint
from .aion_source_cohort import round_clients
from . import source_profiles

FILES = ("agent/Aion/SA_ClientAgent.py", "agent/Aion/SA_Aggregator.py",
         "agent/Aion/HPRF/hprf.py", "agent/Aion/HPRF/initialization_values",
         "agent/Aion/HPRF/matrix", "util/crypto/secretsharing/vss.py", "agent/Aion/bft.py",
         "util/param.py")


def source_inventory(root):
    root = Path(root)
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES}


def source_committee(root, seed, size, clients):
    """Execute source ChaCha20 selection without importing its whole kernel."""
    from Cryptodome.Cipher import ChaCha20
    path = Path(root) / "util/param.py"
    tree = ast.parse(path.read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                    and n.name == "choose_committee")
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ("vector_type", "nonce"):
                values[name] = ast.literal_eval(node.value)
    namespace = dict(np=np, ChaCha20=ChaCha20, **values)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
    return _plain(list(namespace["choose_committee"](seed, size, clients)))


class SourceMessage:
    def __init__(self, body):
        self.body = body


def _plain(value):
    if isinstance(value, np.ndarray):
        return _plain(value.tolist())
    if isinstance(value, (np.integer, gmpy2.mpz)):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _source_class(path, name, methods, namespace):
    tree = ast.parse(path.read_text())
    original = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name)
    body = [n for n in original.body if isinstance(n, ast.FunctionDef)
            and (methods is None or n.name in methods)]
    if methods is not None and {n.name for n in body} != set(methods):
        raise ProtocolError("author source methods missing")
    adapted = ast.ClassDef(name=name, bases=[], keywords=[], body=body, decorator_list=[])
    module = ast.fix_missing_locations(ast.Module(body=[adapted], type_ignores=[]))
    exec(compile(module, str(path), "exec"), namespace)
    return namespace[name]


@lru_cache(maxsize=8)
def load_source(root, inventory_json):
    root = Path(root)
    if source_inventory(root) != json.loads(inventory_json):
        raise ProtocolError("author source snapshot hash mismatch")
    hprf = OriginalAionHPRF.from_directory(root / "agent/Aion/HPRF")

    def load_initialization_values(_filename):
        return hprf.n, hprf.m, hprf.p, hprf.q

    def HPRF(n, m, p, q, _filename):
        if (n, m, p, q) != (hprf.n, hprf.m, hprf.p, hprf.q):
            raise ProtocolError("author HPRF setup mismatch")
        return hprf

    namespace = dict(np=np, os=os, random=random, time=time, re=re, gmpy2=gmpy2,
                     Message=SourceMessage, HPRF=HPRF,
                     load_initialization_values=load_initialization_values)
    client = _source_class(root / FILES[0], "SA_ClientAgent",
        {"sendVectors", "share_mask_seed", "vss_share", "sum_shares", "get_sum_shares"}, namespace)
    aggregator = _source_class(root / FILES[1], "SA_AggregatorAgent",
        {"MMF", "report_process", "reconstruction_process"}, namespace)
    vss = _source_class(root / "util/crypto/secretsharing/vss.py", "VSS", None, namespace)
    return client, aggregator, vss, hprf


def source_request(config, state, request):
    """One node's Flower request; state includes only this node's private data."""
    manifest = json.loads(Path(config["aion-source-manifest"]).read_text())
    if manifest.get("research-only") is not True:
        raise ProtocolError("author source port requires research opt-in")
    client, aggregator, VSS, hprf = load_source(
        manifest["source-root"], json.dumps(manifest["source-sha256"], sort_keys=True))
    source_profiles.validate_profile(manifest, hprf)
    source_profiles.pin_profile(manifest, state)
    actor_id = int(config["aion-source-id"])
    from . import aion_source_sharing as sharing
    encrypted_sharing = sharing.enabled(manifest)
    transport_identity = sharing.identity_for(config, manifest) if encrypted_sharing else None
    is_client = actor_id in manifest["clients"]
    if not is_client and actor_id != manifest["aggregator"]:
        raise ProtocolError("unknown author role")
    action = request["action"]
    from .aion_source_roster import enabled as roster_enabled
    roster_enabled(manifest)  # Reject unknown profiles instead of downgrading.
    from . import aion_source_aggregate as aggregate_validation
    validate_aggregate = aggregate_validation.enabled(manifest)
    if "paper_numerics" in manifest:
        from .source_paper_numeric import filter_rule, scale_source
        filter_rule(manifest)  # Validate before hello or cached replies.
        scale_source(manifest)
    if action == "hello":
        return dict(actor=actor_id, role="client" if is_client else "aggregator",
                    task=manifest["task"], config=digest(manifest))
    if request.get("task") != manifest["task"]:
        raise ProtocolError("source request task mismatch")
    round_id = request.get("round")
    if type(round_id) is not int or not 1 <= round_id <= manifest["rounds"]:
        raise ProtocolError("invalid author round")
    if action.startswith("bft-"):
        from .aion_source_bft import source_bft_request
        return source_bft_request(manifest, actor_id, state, request)
    cache_key = f"{action}/{round_id}"
    tag = digest(request)
    if action in ("enroll", "mask", "select", "reconstruct") and cache_key in state.get("replies", {}):
        cached = state["replies"][cache_key]
        if cached["request"] != tag:
            raise ProtocolError("conflicting author retry")
        return cached["response"]
    if action in ("enroll", "mask", "select", "reconstruct") and cache_key in state.get("expired_replies", {}):
        if state["expired_replies"][cache_key] != tag:
            raise ProtocolError("conflicting author retry")
        raise ProtocolError("expired author retry: only the current round response is retained")
    outbox = []
    learning = manifest.get("workload", "ones") != "ones"
    paper = learning and "paper_numerics" in manifest
    from . import aion_source_selection as selection_auth
    authorize_selection = selection_auth.enabled(manifest)
    if authorize_selection and (not paper or not encrypted_sharing):
        raise ProtocolError("source selection authorization requires encrypted paper-MGF path")
    if paper and manifest["paper_numerics"].get("wire_encoding", "decimal") != "decimal":
        raise ProtocolError("unsupported source precision; exact-scale wire is publicly invertible")
    if paper and manifest["workload"] == "fmnist" and (
            manifest["paper_numerics"].get("reference_sha256") !=
            manifest.get("training", {}).get("input_sha256", {}).get("reference.npz")):
        raise ProtocolError("paper bootstrap is not bound to the staged public checkpoint")
    codec = (source_profiles.update_codec(manifest, hprf)
             if learning else None)
    vss = VSS.__new__(VSS)
    if encrypted_sharing:
        from .crypto import MODULUS, ORDER, GENERATOR, PEDERSEN_GENERATOR
        state.setdefault("vss", dict(p=MODULUS, q=ORDER, g=GENERATOR, h=PEDERSEN_GENERATOR))
    elif "vss" not in state:
        initialized = VSS(prime=manifest["prime"])
        state["vss"] = _plain(dict(p=initialized.p, q=initialized.q,
                                   g=initialized.g, h=initialized.h))
    vss.__dict__.update(state["vss"])
    actor = SimpleNamespace(id=actor_id, num_clients=len(manifest["clients"]),
        vector_len=manifest["dimension"], current_iteration=round_id,
        prime=manifest["prime"], vss=vss, user_committee=manifest["committee"],
        AggregatorAgentID=manifest["aggregator"],
        timings={name: [0] for name in ("Seed sharing", "REPORT", "RECONSTRUCTION",
                                      "Aggregate share reconstruction", "Model aggregation")},
        agent_print=lambda *_: None)
    actor.sendMessage = lambda recipient, message, **_: outbox.append(
        dict(recipient=recipient, body=_plain(message.body)))
    def share_mask_seed():
        if encrypted_sharing:
            outbox.extend(sharing.share_seed(manifest, transport_identity, actor.mask_seed))
        else:
            client.share_mask_seed(actor)
    if is_client and action == "enroll":
        if not learning or round_id != 1 or "mask_seed" in state:
            raise ProtocolError("source enrollment is one-time learning initialization")
        actor.share_mask_seed = share_mask_seed
        actor.vss_share = MethodType(client.vss_share, actor)
        actor.mask_seed = source_profiles.sample_key(manifest, hprf)
        actor.share_mask_seed()
        state["mask_seed"] = actor.mask_seed
        response = dict(outbox=outbox)
    elif is_client and action == "mask":
        dynamic = "cohort_schedule" in manifest
        if actor_id not in round_clients(manifest, round_id):
            raise ProtocolError("client not scheduled for source round")
        if ((not dynamic and round_id != state.get("last_mask_round", 0) + 1)
                or (dynamic and (round_id <= state.get("last_mask_round", 0) or "mask_seed" not in state))):
            raise ProtocolError("source mask round out of order")
        actor.share_mask_seed = share_mask_seed
        actor.vss_share = MethodType(client.vss_share, actor)
        if round_id > 1:
            actor.mask_seed = state["mask_seed"]
        if learning:
            previous = request["model"]
            weights = np.asarray(previous["model"], dtype=float)
            if (previous.get("round") != round_id - 1 or weights.shape != (actor.vector_len,)
                    or not np.isfinite(weights).all()):
                raise ProtocolError("invalid source learning model")
            proof = previous["commit"]
            registry = state.setdefault("learning_registry", proof["registry"])
            from .aion_source_bft import check_source_commit
            if round_id == 1:
                if np.any(weights):
                    raise ProtocolError("source learning genesis must be zero offset")
                value = digest(dict(msg="VALID_CLIENTS", iteration=0, valid_clients=manifest["clients"]))
            else:
                body = previous["body"]
                if (body.get("msg") != "FINAL_SUM" or body.get("iteration") != round_id - 1
                        or body.get("task") != manifest["task"] or body.get("model") != previous["model"]):
                    raise ProtocolError("source learning model differs from committed body")
                value = digest(body)
            check_source_commit(manifest, proof, registry, 2 * (round_id - 1) + 1, value)
            if "mask_seed" in state:
                actor.mask_seed = state["mask_seed"]
            else:
                actor.mask_seed = source_profiles.sample_key(manifest, hprf)
                actor.share_mask_seed()
            if manifest["workload"] == "synthetic":
                from .task import local_delta
                delta = local_delta(weights, actor_id, manifest["learning_rate"])
            elif manifest["workload"] == "fmnist":
                import torch
                from .fmnist import FmnistTrainer
                torch.set_num_threads(1)
                pinned = manifest.get("training", {})
                if pinned:
                    for name, key in ((f"client-{actor_id}.npz", "fmnist-shard"), ("reference.npz", "fmnist-reference")):
                        if hashlib.sha256(Path(config[key]).read_bytes()).hexdigest() != pinned["input_sha256"][name]:
                            raise ProtocolError("source learning input hash changed")
                    if (int(config.get("fmnist-seed", 0)) != pinned["seed"]
                            or int(config.get("fmnist-epochs", 2)) != pinned["epochs"]):
                        raise ProtocolError("source learning training config differs")
                    if config.get("fmnist-attack"):
                        for name, key in (("attack-clean.npz", "clean_path"), ("attack-poison.npz", "poison_path")):
                            if hashlib.sha256(Path(config["fmnist-attack"][key]).read_bytes()).hexdigest() != pinned["input_sha256"][name]:
                                raise ProtocolError("source attack input hash changed")
                trainer = FmnistTrainer(config["fmnist-shard"], config["fmnist-reference"],
                    seed=int(config.get("fmnist-seed", 0)), epochs=int(config.get("fmnist-epochs", 2)),
                    batch_size=int(config.get("fmnist-batch-size", 64)),
                    sampling_policy="author-loader", attack=config.get("fmnist-attack"))
                delta = trainer(weights, actor_id, manifest["learning_rate"], round_id)
            else:
                raise ProtocolError("unknown source learning workload")
            encoded = codec.encode(delta)
            masks = hprf.hprf(actor.mask_seed, round_id, actor.vector_len)
            wire_meta = {}
            if paper:
                from .source_paper_numeric import paper_codec, descriptor, mask_integer_wire
                previous_linf = None if round_id == 1 else previous["body"]["paper_numeric"]["next_linf"]
                pc = paper_codec(manifest, hprf, round_id, previous_linf)
                vector = mask_integer_wire(pc, encoded, masks)
                wire_meta["paper_scale"] = descriptor(pc)
            else:
                vector = [x * codec.padding + h % hprf.p for x, h in zip(encoded, masks, strict=True)]
            body = dict(msg="VECTOR",
                iteration=round_id, sender=actor_id, masked_vector=vector,
                parent=digest(previous["model"]), **wire_meta)
            if authorize_selection:
                body = selection_auth.sign_vector(manifest, transport_identity, body)
            actor.sendMessage(actor.AggregatorAgentID, SourceMessage(body))
        else:
            client.sendVectors(actor, None)
        state.update(mask_seed=actor.mask_seed, last_mask_round=round_id)
        response = dict(outbox=outbox)
    elif is_client and action == "deliver-share":
        if actor_id not in manifest["committee"] or round_id != 1:
            raise ProtocolError("source shares are one-time committee deliveries")
        body = request["body"]
        sender = body.get("sender")
        if body.get("msg") != "SHARED_MASK" or sender not in manifest["clients"]:
            raise ProtocolError("invalid author share delivery")
        expected_index = manifest["committee"].index(actor_id) + 1
        if encrypted_sharing:
            sharing.receive_seed(manifest, transport_identity, state, body)
        else:
            share = body["shared_mask"]
            if len(share) != 3 or any(type(x) is not int for x in share) or share[0] != expected_index:
                raise ProtocolError("wrong author share recipient")
            shares = state.setdefault("shares", {})
            if str(sender) in shares and shares[str(sender)] != body:
                raise ProtocolError("conflicting one-time author share")
            shares[str(sender)] = body
        response = dict(received=True)
    elif is_client and action == "sum-shares":
        if actor_id not in manifest["committee"]:
            raise ProtocolError("only source committee members sum shares")
        members = request["members"]
        if (not members or len(set(members)) != len(members)
                or any(type(i) is not int or i not in round_clients(manifest, round_id) for i in members)):
            raise ProtocolError("invalid source selected members")
        stored = state.get("shares", {})
        if any(str(name) not in stored for name in members):
            raise ProtocolError("missing one-time author share")
        if encrypted_sharing:
            if len(members) < 2:
                raise ProtocolError("source aggregate requires at least two selected members")
            if authorize_selection:
                authorized = state.get("source-selection", {})
                if authorized.get("round") != round_id or authorized.get("members") != members:
                    raise ProtocolError("source key release requires masked MGF authorization")
        from .aion_source_roster import require_commit
        require_commit(manifest, state, request, members)
        if encrypted_sharing:
            # A retry may release the same sum, never a second subset's sum
            # from the same round. Across-round CCS protection is separate.
            tag = digest(sorted(members))
            releases = state.setdefault("source-key-releases", {})
            if str(round_id) in releases and releases[str(round_id)] != tag:
                raise ProtocolError("conflicting source aggregate key release")
            releases[str(round_id)] = tag
        actor.receive_mask_shares = {int(k): tuple(v["shared_mask"]) for k, v in stored.items()}
        response = (sharing.sum_keys(manifest, transport_identity, stored, members, round_id)
                    if encrypted_sharing else dict(sum_shares=_plain(client.get_sum_shares(actor, members))))
    elif action == "stage-vectors" and (not is_client or
            (authorize_selection and actor_id in manifest["committee"])):
        from .aion_source_inbox import stage_vectors
        response = stage_vectors(config, manifest, state, round_id, request["vectors"])
    elif is_client and action == "authorize-selection" and authorize_selection:
        if actor_id not in manifest["committee"]:
            raise ProtocolError("only source committee authorizes masked selections")
        if "vector_refs" in request:
            if "vectors" in request:
                raise ProtocolError("mixed inline and staged source vectors")
            from .aion_source_inbox import load_vectors
            vectors = load_vectors(config, manifest, state, round_id, request["vector_refs"])
        else:
            vectors = request["vectors"]
        response = selection_auth.authorize(manifest, transport_identity, state, request,
                                            vectors, hprf, codec.max_integer)
    elif is_client and action == "validate-aggregate" and validate_aggregate:
        response = aggregate_validation.validate(manifest, transport_identity, state, request, hprf)
    elif not is_client and action == "select":
        if round_id != state.get("last_round", 0) + 1:
            raise ProtocolError("source selection round out of order")
        if "vector_refs" in request:
            from .aion_source_inbox import load_vectors
            if "vectors" in request:
                raise ProtocolError("mixed inline and staged source vectors")
            vectors = load_vectors(config, manifest, state, round_id, request["vector_refs"])
        else:
            vectors = request["vectors"]
        if (not vectors or len({v["sender"] for v in vectors}) != len(vectors)
                or {v["sender"] for v in vectors} != set(round_clients(manifest, round_id))
                or any(v.get("msg") != "VECTOR" or v.get("iteration") != round_id
                       or v.get("sender") not in manifest["clients"]
                       or len(v.get("masked_vector", [])) != manifest["dimension"] for v in vectors)):
            raise ProtocolError("invalid original VECTOR cohort")
        if learning:
            parent = digest(state.get("model", [0.0] * actor.vector_len))
            limit = codec.max_integer * codec.padding
            upper = hprf.p + limit
            if paper:
                from .source_paper_numeric import paper_codec
                from .paper_dmc import round_even
                pc = paper_codec(manifest, hprf, round_id, state.get("paper_next_linf"))
                limit = codec.max_integer * (pc.denominator // codec.scale)
                upper = limit + round_even(pc.coefficient * hprf.p) + 1
            if any(v.get("parent") != parent or any(type(x) is not int or not -limit <= x <= upper
                   for x in v["masked_vector"]) for v in vectors):
                raise ProtocolError("invalid integer learning VECTOR or parent")
        actor.user_masked_vectors = {v["sender"]: np.asarray(v["masked_vector"], dtype=object if learning else np.float64)
                                    for v in vectors}
        # Only the source norm computation sees float64. Aggregation retains
        # integer coordinates; otherwise 64-bit masks erase small gradients.
        if learning:
            actor.MMF = lambda updates, *args: aggregator.MMF(actor,
                {k: np.asarray(v, dtype=np.float64) for k, v in updates.items()}, *args)
        else:
            actor.MMF = MethodType(aggregator.MMF, actor)
        actor.l2_old = state.get("l2_old", [])
        actor.linf_old = state.get("linf_old", 0.1)
        actor.linf_HPRF_old = state.get("linf_HPRF_old", 0.05)
        actor.b_old = state.get("b_old", 0.2)
        if paper:
            from .source_paper_numeric import paper_codec, descriptor, select_masked
            pc = paper_codec(manifest, hprf, round_id, state.get("paper_next_linf"))
            if any(v.get("paper_scale") != descriptor(pc) for v in vectors):
                raise ProtocolError("paper vector scale differs from committed public history")
            if authorize_selection:
                selection_auth.check_vectors(manifest, vectors, round_id, parent, pc, codec.max_integer)
                vectors = sorted(vectors, key=lambda v: v["sender"])
            pending = select_masked(manifest, state, pc, vectors, round_id)
            actor.selected_indices, actor.b_old, actor.vec_sum_partial = (
                pending["selected"], pending["bound"], pending["total"])
        else:
            aggregator.report_process(actor)
        if len(actor.selected_indices) < 1:
            raise ProtocolError("original MMF selected no clients")
        state["pending"] = _plain(dict(round=round_id, selected=actor.selected_indices,
                                      total=actor.vec_sum_partial, bound=actor.b_old))
        if paper:
            state["pending"] = pending
        response = dict(selected=actor.selected_indices, bound=float(actor.b_old))
    elif not is_client and action == "reconstruct":
        pending = state.get("pending", {})
        if pending.get("round") != round_id:
            raise ProtocolError("missing original selection")
        entries = request["shares"]
        if (not encrypted_sharing or "threshold_rule" not in manifest["sharing_profile"]) and (
                len({e["sender"] for e in entries}) != len(entries) or any(
                    e["sender"] not in manifest["committee"] for e in entries)):
            raise ProtocolError("invalid original committee replies")
        actor.committee_threshold = (sharing.threshold(manifest) if encrypted_sharing
                                    else max(2, len(manifest["committee"]) // 3))
        actor.committee_shares_sum = ({e["sender"]: e["sum_shares"] for e in entries}
                                     if not encrypted_sharing else {})
        actor.vec_sum_partial = np.asarray(pending["total"], dtype=object)
        actor.selected_indices = pending["selected"]
        actor.hprf_prime = load_source(manifest["source-root"],
            json.dumps(manifest["source-sha256"], sort_keys=True))[3].p
        actor.l2_old = state.get("l2_old", [])
        # Expose the source callback explicitly. This is NOT a BFT certificate.
        actor._bft_broadcast_with_consensus = lambda message, recipients: (
            outbox.append(dict(kind="source-bft-required", recipients=recipients,
                               body=_plain(message.body))) or {}, 0)
        if learning:
            if not encrypted_sharing and len(actor.committee_shares_sum) < actor.committee_threshold:
                raise ProtocolError("source learning shares below threshold")
            if validate_aggregate:
                opening = sharing.recover_key_opening(manifest, transport_identity, entries,
                                                     pending["selected"], round_id)
                actor.seed_sum = opening["key"]
            else:
                actor.seed_sum = (sharing.recover_key(manifest, transport_identity, entries,
                    pending["selected"], round_id) if encrypted_sharing else
                    actor.vss.reconstruct(list(actor.committee_shares_sum.values()), actor.prime))
            paper_metadata = {}
            if paper:
                from .source_paper_numeric import paper_codec, recover
                pc = paper_codec(manifest, hprf, round_id, state.get("paper_next_linf"))
                decoded, meta = recover(manifest, state, pc, hprf, round_id, pending, actor.seed_sum)
                paper_metadata["paper_numeric"] = meta
            else:
                decoded = codec.unmask(pending["total"], actor.seed_sum, manifest["task"], round_id,
                                       len(pending["selected"]))
            mean = [x / (codec.scale * len(pending["selected"])) for x in decoded]
            previous_model = state.get("model", [0.0] * actor.vector_len)
            model = [w + x for w, x in zip(previous_model, mean, strict=True)]
            # The source floor division is for its ones-vector benchmark, not
            # a quantized signed learning mean. Decode the sum, then divide.
            actor.final_sum = np.asarray(mean)
            actor.l2_old = [float(np.linalg.norm(mean))] + state.get("l2_old", [])[:1]
            actor.linf_old = max(abs(x) for x in mean)
            actor.linf_HPRF_old = max(hprf.hprf(actor.seed_sum, round_id, actor.vector_len))
            state["model"] = model
            outbox.append(dict(kind="source-bft-required", recipients=manifest["committee"],
                body=dict(msg="FINAL_SUM", iteration=round_id, task=manifest["task"],
                          final_sum=mean, model=model, **paper_metadata)))
            if paper:
                state["paper_next_linf"] = meta["next_linf"]
                state["paper_bound"] = meta["bound"]
                state["paper_terms"] = (state.get("paper_terms", []) + [meta["history_term"]])[-2:]
                if "mgf_scope" in meta:
                    state["paper_mgf_scope"] = meta["mgf_scope"]
        else:
            aggregator.reconstruction_process(actor)
        state.update(last_round=round_id, b_old=pending["bound"],
                     l2_old=_plain(actor.l2_old), linf_old=float(actor.linf_old),
                     linf_HPRF_old=float(actor.linf_HPRF_old))
        response = dict(result=_plain(actor.final_sum), outbox=outbox,
                        source_bft_committed=False, **({"model": state["model"]} if learning else {}))
        if validate_aggregate:
            response["aggregate_opening"] = opening
    else:
        raise ProtocolError("unknown author source action or role")
    state["vss"] = _plain(dict(p=vss.p, q=vss.q, g=vss.g, h=vss.h))
    if action in ("enroll", "mask", "select", "reconstruct"):
        replies = state.setdefault("replies", {})
        # Ray transfers Context on each invocation. Keeping every full model
        # and VECTOR reply would grow that transfer with the round count.
        # Keep the current round for transport retries, and only request hashes
        # for old rounds so an expired retry cannot re-execute or reshare keys.
        for key in list(replies):
            if int(key.rsplit("/", 1)[1]) < round_id:
                state.setdefault("expired_replies", {})[key] = replies.pop(key)["request"]
        replies[cache_key] = dict(request=tag, response=response)
    return _plain(response)


def flower_source_request(config, context_state, request):
    saved = context_state.get("aion-source-state")
    state = json.loads(saved["snapshot"]) if saved else {}
    response = source_request(config, state, request)
    context_state["aion-source-state"] = ConfigRecord({"snapshot": canonical(state)})
    return response

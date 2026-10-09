"""Execute the author's ASR normal path over Flower Message transport.

The default preserves the author's ones-vector workload. Optional synthetic and
FMNIST workloads use an integer learning adapter with the source MMF filter;
they do not reproduce the separate author training artifact's MGF algorithm.
Source BFT events are routed through the committee's three voting phases.
"""

import argparse
import hashlib
import json
import os
import shutil
import uuid
import time
from pathlib import Path

import numpy as np

from flwr.app import ConfigRecord, Context, RecordDict
from flwr.serverapp import ServerApp

from .aion_source_asr import FILES, source_inventory, source_committee
from .client_app import payload, records
from .crypto import Identity, MODULUS, ORDER, ProtocolError, canonical
from .local_grid import ProcessGrid, PooledProcessGrid
from .aion_source_cohort import make_cohorts, round_clients
from . import aion_source_roster as roster_consensus


def provision_source(output, source, *, clients=10, committee=4, dimension=8, rounds=4,
                     committee_members=None, workload="ones", decimals=6, max_abs=100.0,
                     learning_rate=0.001, cohort_schedule=None, paper_numerics=None,
                     source_profile=None):
    output, source = Path(output), Path(source)
    if not 2 <= committee <= clients or min(dimension, rounds) < 1:
        raise ValueError("require clients >= committee >= 2 and positive dimension/rounds")
    if workload not in ("ones", "synthetic", "fmnist") or (workload != "ones" and clients < 7):
        raise ValueError("source learning requires at least seven clients for MMF's minimum two survivors")
    if not 0 < learning_rate <= 1:
        raise ValueError("invalid source learning rate")
    if workload == "fmnist" and dimension != 61706:
        raise ValueError("source FMNIST requires the full LeNet dimension")
    if paper_numerics is not None:
        from .paper_dmc import rational
        from .source_paper_numeric import (FILTER_RULE, LEGACY_FILTER_RULE,
                                          SUM_SCALE_SOURCE, LEGACY_SCALE_SOURCE)
        projection = paper_numerics.get("projection", [])
        if (workload == "ones" or clients < 20 or len(projection) != 2
                or any(type(v) is not int for v in projection)
                or not 0 <= projection[0] < projection[1] <= dimension
                or rational(paper_numerics["initial_linf"]) <= 0
                or rational(paper_numerics["beta"]) != rational("0.2")
                or paper_numerics.get("wire_encoding", "decimal") != "decimal"
                or paper_numerics.get("scale_source", SUM_SCALE_SOURCE) not in (
                    SUM_SCALE_SOURCE, LEGACY_SCALE_SOURCE)
                or paper_numerics.get("filter_rule", FILTER_RULE) not in (FILTER_RULE, LEGACY_FILTER_RULE)):
            raise ValueError("invalid experimental paper numeric options")
    if cohort_schedule is not None:
        if workload == "ones":
            raise ValueError("dynamic source cohorts require a learning workload")
        check = dict(clients=list(range(clients)), rounds=rounds, cohort_schedule=cohort_schedule)
        for r in range(1, rounds + 1):
            round_clients(check, r)
            if paper_numerics is not None and len(round_clients(check, r)) < 20:
                raise ValueError("paper-scale path requires >=20 candidates each round")
    if committee_members is not None and (len(committee_members) != committee
            or len(set(committee_members)) != committee
            or any(type(v) is not int or not 0 <= v < clients for v in committee_members)):
        raise ValueError("invalid explicit author committee")
    # Validate the opt-in numeric envelope BEFORE creating a task or identities.
    key_policy = dict(kind="author-scalar", minimum=1, maximum=100000,
                      production_privacy=False)
    if source_profile is not None:
        from . import source_profiles
        from .aion_original_hprf import OriginalAionHPRF
        hprf = OriginalAionHPRF.from_directory(source / "agent/Aion/HPRF")
        opts = source_profiles.profile(dict(source_profile=source_profile))
        if opts["key_domain"] == "author-full-q":
            key_policy.update(minimum=0, maximum=hprf.q - 1, modulus=hprf.q)
        preview = dict(source_profile=opts, key_profile=key_policy,
            **{"research-only": True}, workload=workload, clients=list(range(clients)),
            max_abs=max_abs, dimension=dimension)
        if paper_numerics is not None:
            preview["paper_numerics"] = {"scale_source": SUM_SCALE_SOURCE, **paper_numerics}
        source_profiles.validate_profile(preview, hprf, transport=False)
    inventory = source_inventory(source)
    output.mkdir(parents=True, exist_ok=False)
    snapshot = output / "author-source"
    for name in FILES:
        target = snapshot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    if source_inventory(snapshot) != inventory:
        raise ValueError("author snapshot copy differs")
    seed = os.urandom(32)
    selected_committee = (list(committee_members) if committee_members is not None
                          else source_committee(snapshot, seed, committee, clients))
    manifest = dict(task=uuid.uuid4().hex, **{"research-only": True,
        "source-root": str(snapshot.resolve()), "source-sha256": inventory},
        clients=list(range(clients)), committee=selected_committee, aggregator=clients,
        committee_seed=seed.hex(), committee_selection="explicit" if committee_members is not None else "author-chacha20",
        dimension=dimension, rounds=rounds, prime=MODULUS,
        key_profile=key_policy,
        sharing_profile=dict(kind="author-fixed-polynomial", threshold_privacy=False,
                             flower_relay="plaintext-individual-shares"),
        selection_consensus=dict(kind=roster_consensus.MODE, subject="post-filter-client-set",
                                 key_release="requires-filtered-bft-commit"),
        workload=workload, decimals=decimals, max_abs=max_abs, learning_rate=learning_rate,
        scope=("author ASR ones-vector + committee BFT normal path; not FMNIST or general liveness"
               if workload == "ones" else "author ASR fixed-key learning adapter; integer encoding; source MMF; normal-path BFT"))
    if source_profile is not None:
        manifest["source_profile"] = dict(source_profile)
    if cohort_schedule is not None:
        manifest["cohort_schedule"] = cohort_schedule
        manifest["scope"] += "; staged dynamic cohorts, upfront population key sharing"
    if paper_numerics is not None:
        manifest["paper_numerics"] = {"filter_rule": FILTER_RULE,
                                     "scale_source": SUM_SCALE_SOURCE, **paper_numerics}
        manifest["scope"] = ("experimental paper-scale single-view masked MGF; original HPRF/one-time VSS; "
            "E2 percentile bootstrap + paper historical ratio; conditional quantized-lift; "
            "public checkpoint bootstrap differs from fixed E2 init; normal-path BFT; not exact author end-to-end")
        manifest["scope"] += "; historical filter rule=" + manifest["paper_numerics"]["filter_rule"]
        manifest["scope"] += "; protocol scale/history units=" + manifest["paper_numerics"]["scale_source"]
    manifest["scope"] += (f"; author scalar keyspace {key_policy['minimum']}..{key_policy['maximum']}; "
                          "no production privacy claim")
    manifest["scope"] += "; post-filter BFT membership binding (paper ordering adapter)"
    if workload != "ones":
        from .aion_original_hprf import OriginalAionHPRF
        from .numeric import FixedPoint
        if source_profile is None or opts["recovery"] != source_profiles.CENTERED:
            FixedPoint(decimals, max_abs, clients, mask_backend="aion-original",
                       original_hprf_setup=OriginalAionHPRF.from_directory(snapshot / "agent/Aion/HPRF").public_setup())
    identities = {}
    if workload != "ones":
        from .aion_source_sharing import MODE, THRESHOLD_RULE
        manifest["prime"] = ORDER
        manifest["sharing_profile"] = dict(kind=MODE, polynomial="csprng-randomized",
            flower_relay="recipient-encrypted-signed-shares", external_crypto_audit=False,
            threshold_rule=THRESHOLD_RULE, threshold=max(2, (committee - 1) // 3 + 1))
        private_dir = output / "private-node-identities"
        private_dir.mkdir(mode=0o700)
        registry = {}
        for actor in range(clients + 1):
            identity = Identity.generate(str(actor))
            identity_path = private_dir / f"{actor}.json"
            identity_path.touch(mode=0o600)
            identity_path.write_bytes(canonical(identity.private()))
            identities[actor] = str(identity_path.resolve())
            registry[str(actor)] = identity.public()
        manifest["source_transport_registry"] = registry
        manifest["scope"] += "; randomized Pedersen key sharing, encrypted recipient-bound relay"
        if paper_numerics is not None:
            from .aion_source_selection import MODE as SELECTION_MODE
            manifest["selection_authorization"] = dict(kind=SELECTION_MODE,
                evidence="client-signed-masked-vectors-and-committed-history")
            manifest["scope"] += "; committee masked-filter replay before key-sum release"
            from .aion_source_aggregate import MODE as AGGREGATE_MODE
            manifest["aggregation_validation"] = dict(kind=AGGREGATE_MODE,
                evidence="local-selected-key-commitments-and-masked-sum-replay",
                opening="authorized-aggregate-only-no-new-client-shares")
            manifest["scope"] += "; committee aggregate/norm replay before model BFT"
    if source_profile is not None:
        source_profiles.validate_profile(manifest, hprf)
        manifest["scope"] += "; explicit source profile=" + opts["recovery"]
        manifest["scope"] += "; history=" + opts["history"] + "; period policy=" + opts["period_policy"]
        if opts["recovery"] == source_profiles.CENTERED:
            manifest["scope"] = manifest["scope"].replace("conditional quantized-lift", "bounded transmission-centered recovery")
    manifest_path = output / "manifest.json"
    manifest_path.write_bytes(canonical(manifest))
    nodes = {index + 1: {"aion-source-manifest": str(manifest_path.resolve()),
                        "aion-source-id": index} for index in range(clients + 1)}
    for actor, path in identities.items():
        nodes[actor + 1]["aion-source-identity"] = path
    return manifest_path, nodes


class AuthorASRWorkflow:
    def __init__(self, manifest, *, timeout=60, on_round=None, vector_batch_bytes=8 * 1024 * 1024):
        self.manifest, self.timeout, self.on_round = manifest, timeout, on_round
        if type(vector_batch_bytes) is not int or not 1 <= vector_batch_bytes <= 8 * 1024 * 1024:
            raise ValueError("invalid source masked batch size")
        self.vector_batch_bytes = vector_batch_bytes
        self.masked_batch_deliveries = 0
        self.masked_batch_max_bytes = 0
        self.nodes = {}
        self.last_request = None
        self.failure_code = "request-rejected"

    def call(self, grid, actors, action, round_id=None, *, actor_payloads=None, **kwargs):
        self.last_request = dict(action=action, round=round_id)
        command = dict(action=action, **kwargs)
        if round_id is not None:
            command.update(task=self.manifest["task"], round=round_id)
        if actor_payloads is not None and (set(actor_payloads) != set(actors)
                or any(set(extra) & {"action", "task", "round"} for extra in actor_payloads.values())):
            raise ProtocolError("invalid source per-actor payloads")
        messages = [grid.create_message(records({**command, **(actor_payloads[actor]
                                       if actor_payloads is not None else {})}), "query.aion_source_asr",
                                       self.nodes[actor], "author-asr", ttl=self.timeout)
                    for actor in actors]
        replies = {}
        inverse = {node: actor for actor, node in self.nodes.items()}
        for reply in grid.send_and_receive(messages, timeout=self.timeout):
            if reply.has_error():
                from .paper_dmc import QuantizedLiftError
                codes = {"Author ASR numeric failure: " + code: code
                         for code in QuantizedLiftError.CODES}
                from .aion_source_aggregate import AggregateValidationError
                codes.update({"Author ASR aggregate validation failure: " + code: code
                              for code in AggregateValidationError.CODES})
                from .source_paper_numeric import MGFSelectionError
                codes.update({"Author ASR MGF selection failure: " + code: code
                              for code in MGFSelectionError.CODES})
                from .source_profiles import SourceProfileError
                codes.update({"Author ASR profile failure: " + code: code
                              for code in SourceProfileError.CODES})
                self.failure_code = codes.get(reply.error.reason, "request-rejected")
                raise ProtocolError(f"author Flower actor rejected request: action={action}, "
                                    f"round={round_id}, category={self.failure_code}")
            actor = inverse[reply.metadata.src_node_id]
            if actor not in actors or actor in replies:
                raise ProtocolError("unexpected author Flower reply")
            replies[actor] = payload(reply)
        if set(replies) != set(actors):
            raise ProtocolError("incomplete author Flower replies")
        return [replies[actor] for actor in actors]

    def select(self, grid, round_id, vectors, *, actors=None, action="select", **kwargs):
        aggregator = self.manifest["aggregator"]
        actors = [aggregator] if actors is None else actors
        if len(canonical(dict(vectors=vectors))) <= self.vector_batch_bytes:
            replies = self.call(grid, actors, action, round_id, vectors=vectors, **kwargs)
            return replies[0] if action == "select" else replies
        references, batch, size = [], [], 0
        for vector in vectors:
            width = len(canonical(vector))
            if width > 8 * 1024 * 1024:
                raise ProtocolError("one source vector exceeds bounded Flower batch")
            if batch and size + width > self.vector_batch_bytes:
                responses = self.call(grid, actors, "stage-vectors", round_id, vectors=batch)
                if any(response != responses[0] for response in responses):
                    raise ProtocolError("source staged vector references disagree")
                response = responses[0]
                self.masked_batch_deliveries += len(actors)
                self.masked_batch_max_bytes = max(self.masked_batch_max_bytes,
                    len(canonical(dict(vectors=batch))))
                references.extend(response["vector_refs"])
                batch, size = [], 0
            batch.append(vector)
            size += width
        if batch:
            responses = self.call(grid, actors, "stage-vectors", round_id, vectors=batch)
            if any(response != responses[0] for response in responses):
                raise ProtocolError("source staged vector references disagree")
            response = responses[0]
            self.masked_batch_deliveries += len(actors)
            self.masked_batch_max_bytes = max(self.masked_batch_max_bytes,
                len(canonical(dict(vectors=batch))))
            references.extend(response["vector_refs"])
        replies = self.call(grid, actors, action, round_id, vector_refs=references, **kwargs)
        return replies[0] if action == "select" else replies

    def run(self, grid):
        from trustlessfl.crypto import digest
        nodes = list(grid.get_node_ids())
        for offset in range(0, len(nodes), 64):
            batch = nodes[offset:offset + 64]
            messages = [grid.create_message(records(dict(action="hello")),
                "query.aion_source_asr", node, "author-asr", ttl=self.timeout) for node in batch]
            seen = set()
            for reply in grid.send_and_receive(messages, timeout=self.timeout):
                if reply.has_error():
                    raise ProtocolError("author discovery rejected")
                node = reply.metadata.src_node_id
                hello = payload(reply)
                actor = hello["actor"]
                if (node not in batch or node in seen
                        or hello["task"] != self.manifest["task"]
                        or hello["config"] != digest(self.manifest) or actor in self.nodes):
                    raise ProtocolError("author discovery mismatch")
                seen.add(node)
                self.nodes[actor] = node
            if seen != set(batch):
                raise ProtocolError("incomplete source discovery batch")
        m = self.manifest
        post_filter_bft = roster_consensus.enabled(m)
        from .aion_source_aggregate import enabled as aggregate_validation_enabled, check_validations
        aggregate_validation = aggregate_validation_enabled(m)
        if set(self.nodes) != set(m["clients"]) | {m["aggregator"]}:
            raise ProtocolError("incomplete source roles")
        deliveries = 0
        if "cohort_schedule" in m:
            enrollments = self.call(grid, m["clients"], "enroll", 1)
            for sender, reply in zip(m["clients"], enrollments, strict=True):
                if len(reply["outbox"]) != len(m["committee"]):
                    raise ProtocolError("incomplete upfront source enrollment")
                routed = {}
                for event in reply["outbox"]:
                    body = event["body"]
                    if (body["sender"] != sender or body["msg"] != "SHARED_MASK"
                            or event["recipient"] not in m["committee"]
                            or event["recipient"] in routed):
                        raise ProtocolError("invalid upfront source enrollment")
                    routed[event["recipient"]] = dict(body=body)
                # Different committee nodes receive concurrently; never issue
                # overlapping state mutations to the same Flower node.
                self.call(grid, m["committee"], "deliver-share", 1, actor_payloads=routed)
                deliveries += len(routed)
        hellos = self.call(grid, m["committee"], "bft-hello", 1)
        registry = {str(h["actor"]): h["public"] for h in hellos}
        legal = self.consensus(grid, 1, digest(dict(msg="VALID_CLIENTS", iteration=0,
                              valid_clients=m["clients"])), registry, sequence=1)
        history, completed_bft, authorized_rounds, validated_rounds = [], 0, 0, 0
        learning = m.get("workload", "ones") != "ones"
        current = dict(round=0, model=[0.0] * m["dimension"], commit=legal) if learning else None
        for r in range(1, m["rounds"] + 1):
            cohort = round_clients(m, r)
            replies = self.call(grid, cohort, "mask", r, **({"model": current} if learning else {}))
            vectors = []
            # All one-time deliveries precede the first share-sum request.
            for sender, reply in zip(cohort, replies, strict=True):
                for event in reply["outbox"]:
                    body = event["body"]
                    if body["sender"] != sender:
                        raise ProtocolError("source outbox sender mismatch")
                    if body["msg"] == "SHARED_MASK":
                        if r != 1 or event["recipient"] not in m["committee"]:
                            raise ProtocolError("source resent key share")
                        self.call(grid, [event["recipient"]], "deliver-share", r, body=body)
                        deliveries += 1
                    elif body["msg"] == "VECTOR" and event["recipient"] == m["aggregator"]:
                        vectors.append(body)
                    else:
                        raise ProtocolError("unexpected source outbox event")
            if len(vectors) != len(cohort):
                raise ProtocolError("source VECTOR cohort incomplete")
            if not post_filter_bft:
                # Explicit compatibility for historical pre-filter runs.
                online = self.consensus(grid, r, digest(dict(msg="ONLINE_CLIENTS", iteration=r,
                    online_clients=[int(name in {v["sender"] for v in vectors}) for name in m["clients"]])),
                    registry, sequence=2 * r)
            selection = self.select(grid, r, vectors)
            from .aion_source_selection import enabled as selection_authorization_enabled, check_authorizations
            authorization_proofs = []
            if selection_authorization_enabled(m):
                authorizations = self.select(grid, r, vectors, actors=m["committee"],
                    action="authorize-selection", model=current, members=selection["selected"])
                if any(auth["selected"] != selection["selected"] or auth["bound"] != selection["bound"]
                       or auth["vectors_digest"] != digest(sorted(vectors, key=lambda v: v["sender"]))
                       for auth in authorizations):
                    raise ProtocolError("source committee selection differs from aggregator")
                authorization_proofs = [auth["authorization"] for auth in authorizations]
                check_authorizations(m, authorization_proofs, r, selection["selected"], selection["bound"],
                    parent=digest(current["model"]), vectors_digest=digest(sorted(vectors, key=lambda v: v["sender"])))
                authorized_rounds += 1
            if post_filter_bft:
                online = self.consensus(grid, r,
                    digest(roster_consensus.statement(m, r, selection["selected"],
                        vectors_digest=digest(sorted(vectors, key=lambda v: v["sender"]))
                        if "source_profile" in m else None)), registry,
                    sequence=2 * r, selection_members=selection["selected"])
            replies = self.call(grid, m["committee"], "sum-shares", r, members=selection["selected"],
                **({"selection_commit": online} if post_filter_bft else {}))
            shares = [dict(sender=name, **response)
                      for name, response in zip(m["committee"], replies, strict=True)]
            final, = self.call(grid, [m["aggregator"]], "reconstruct", r, shares=shares)
            events = final["outbox"]
            if final["source_bft_committed"] or any(e["kind"] != "source-bft-required" for e in events):
                raise ProtocolError("source BFT status misrepresented")
            proofs = []
            aggregate_proofs = []
            for event in events:
                value = digest(event["body"])
                if aggregate_validation:
                    approvals = self.call(grid, m["committee"], "validate-aggregate", r,
                        body=event["body"], opening=final["aggregate_opening"])
                    if any(not approval.get("verified") or approval.get("value") != value
                           for approval in approvals):
                        raise ProtocolError("source committee aggregate replay differs")
                    aggregate_proofs = [approval["authorization"] for approval in approvals]
                    check_validations(m, aggregate_proofs, r, selection["selected"], event["body"],
                        parent=digest(current["model"]),
                        vectors_digest=digest(sorted(vectors, key=lambda v: v["sender"])))
                    validated_rounds += 1
                proofs.append(self.consensus(grid, r, value, registry, sequence=2 * r + 1))
                completed_bft += 1
            if learning:
                current = dict(round=r, model=final["model"], body=events[0]["body"], commit=proofs[0])
            if self.on_round is not None:
                self.on_round(r, vectors, shares, selection, final)
            history.append(dict(round=r, selected=selection["selected"], bound=selection["bound"],
                                result=final["result"], source_bft=proofs, online_bft=online,
                                **({"selection_authorizations": authorization_proofs} if authorization_proofs else {}),
                                **({"aggregate_validations": aggregate_proofs} if aggregate_proofs else {}),
                                **({"online_clients": cohort} if "cohort_schedule" in m else {}),
                                **({"model": final["model"]} if learning else {}),
                                **({"paper_numeric": events[0]["body"]["paper_numeric"]}
                                   if "paper_numerics" in m else {})))
        return dict(history=history, key_share_deliveries=deliveries, mask_share_deliveries=0,
                    selection_authorized_rounds=authorized_rounds,
                    aggregate_validated_rounds=validated_rounds,
                    masked_batch_deliveries=self.masked_batch_deliveries,
                    masked_batch_max_bytes=self.masked_batch_max_bytes,
                    source_bft_completed_events=completed_bft,
                    source_bft_committed=True, legal_bft=legal, scope=m["scope"])

    def consensus(self, grid, round_id, value, registry, *, sequence=None, selection_members=None):
        committee = self.manifest["committee"]
        sequence = round_id if sequence is None else sequence
        request = dict(value=value, registry=registry, sequence=sequence)
        if selection_members is not None:
            request["selection_members"] = selection_members
        replies = self.call(grid, committee, "bft-prepare", round_id, **request)
        messages = [reply["response"] for reply in replies]
        for phase in ("prepare", "precommit", "commit"):
            if any(message is None or message["type"] != phase for message in messages):
                raise ProtocolError("source BFT phase unavailable")
            emitted, decisions = {}, {}
            for message in messages:
                replies = self.call(grid, committee, "bft-deliver", round_id,
                                    message=message, **request)
                for reply in replies:
                    decisions[reply["actor"]] = reply["decided"]
                    if reply["response"] is not None:
                        emitted[reply["actor"]] = reply["response"]
            if phase == "commit":
                if not all(decisions.values()) or set(decisions) != set(committee):
                    raise ProtocolError("source BFT commit incomplete")
                from .aion_source_bft import check_source_commit
                proof = dict(value=value, sequence=sequence, registry=registry, commits=messages)
                return check_source_commit(self.manifest, proof, registry, sequence, value)
            messages = list(emitted.values())
        raise ProtocolError("source BFT did not decide")


app = ServerApp()


@app.main()
def main(grid, context):
    manifest = json.loads(Path(context.run_config["aion-source-manifest"]).read_text())
    completed = []
    def committed(r, vectors, shares, selection, final):
        completed.append(dict(round=r, selected=selection["selected"],
            **({"paper_numeric": final["outbox"][0]["body"]["paper_numeric"]}
               if "paper_numerics" in manifest else {})))
    workflow = AuthorASRWorkflow(manifest, on_round=committed)
    try:
        result = workflow.run(grid)
    except ProtocolError:
        context.state["aion-source-failure"] = ConfigRecord({"failure": canonical(dict(
            status="failed", request=workflow.last_request, category=workflow.failure_code,
            completed_rounds=completed, requested_rounds=manifest["rounds"],
            scope="public committed metadata only; failed round not committed"))})
        raise
    context.state["aion-source-result"] = ConfigRecord({"result": canonical(result)})


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clients", type=int, default=10)
    parser.add_argument("--participants", type=int, help="Dynamic per-round client count, learning only")
    parser.add_argument("--participation-seed", type=int, default=0)
    parser.add_argument("--committee", type=int, default=4)
    parser.add_argument("--workers", type=int, help="Bounded local simulation workers (default: 4 for large populations)")
    parser.add_argument("--dimension", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--workload", choices=("ones", "synthetic", "fmnist"), default="ones")
    parser.add_argument("--decimals", type=int, default=6)
    parser.add_argument("--max-abs", type=float, default=100.0)
    parser.add_argument("--source-profile", type=Path,
        help="Explicit research source profile JSON; existing task defaults are preserved")
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--fmnist-inputs", type=Path, help="Existing staged FMNIST inputs directory")
    parser.add_argument("--paper-quantized-mgf", action="store_true",
        help="Experimental no-extra-share paper-scale MGF with public checkpoint bootstrap; fail on ambiguous lift")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--attack-clients", type=int, default=0)
    parser.add_argument("--attack-rounds", type=int, nargs="*", default=[])
    args = parser.parse_args()
    if args.workers is not None and not 1 <= args.workers <= args.clients + 1:
        parser.error("invalid source worker count")
    if (args.epochs < 1 or not 0 <= args.attack_clients <= args.clients
            or any(r < 1 or r > args.rounds for r in args.attack_rounds)
            or (args.attack_clients and not args.attack_rounds)
            or (args.attack_clients and args.workload != "fmnist")):
        parser.error("invalid source learning attack/training settings")
    if args.workload == "fmnist":
        if args.fmnist_inputs is None:
            parser.error("fmnist requires --fmnist-inputs")
        args.dimension = 61706
    paper_options = None
    if args.paper_quantized_mgf:
        if args.workload != "fmnist" or (args.participants or args.clients) < 20:
            parser.error("paper-quantized-mgf requires FMNIST and >=20 participants")
        from fractions import Fraction
        reference = args.fmnist_inputs / "reference.npz"
        with np.load(reference, allow_pickle=False) as archive:
            weights = archive["weights"]
        paper_options = dict(initial_linf=str(Fraction(float(np.max(np.abs(weights[-850:-10]))))),
            beta="0.2", projection=[61706 - 850, 61706 - 10],
            bootstrap="public-classifier-checkpoint-not-E2-fixed-one",
            reference_sha256=hashlib.sha256(reference.read_bytes()).hexdigest())
    schedule = (make_cohorts(args.clients, args.participants, args.rounds,
        malicious=args.attack_clients, attack_rounds=args.attack_rounds, seed=args.participation_seed)
        if args.participants is not None else None)
    manifest, nodes = provision_source(args.output, args.source, clients=args.clients,
        committee=args.committee, dimension=args.dimension, rounds=args.rounds,
        workload=args.workload, decimals=args.decimals, max_abs=args.max_abs,
        learning_rate=args.learning_rate, cohort_schedule=schedule, paper_numerics=paper_options,
        source_profile=json.loads(args.source_profile.read_text()) if args.source_profile else None)
    if schedule is not None:
        data = json.loads(manifest.read_text())
        data["participation"] = dict(participants=args.participants, seed=args.participation_seed,
                                     rule="author-individual-inclusion-isolated-rng")
        manifest.write_bytes(canonical(data))
    if args.workload == "fmnist":
        inputs = args.fmnist_inputs.resolve()
        names = ["reference.npz", *[f"client-{i}.npz" for i in range(args.clients)]]
        if args.attack_clients:
            names += ["attack-clean.npz", "attack-poison.npz"]
        pinned = {name: hashlib.sha256((inputs / name).read_bytes()).hexdigest() for name in names}
        data = json.loads(manifest.read_text())
        data["training"] = dict(epochs=args.epochs, seed=0, input_sha256=pinned,
            input_root=str(inputs), attack_clients=args.attack_clients, attack_rounds=args.attack_rounds,
            attack_steps=120, attack_boost=20.0, poison_batch=6)
        manifest.write_bytes(canonical(data))
        for i in range(args.clients):
            nodes[i + 1].update({"fmnist-shard": str(inputs / f"client-{i}.npz"),
                "fmnist-reference": str(inputs / "reference.npz"), "fmnist-seed": 0,
                "fmnist-epochs": args.epochs, "fmnist-batch-size": 64})
            if i < args.attack_clients:
                nodes[i + 1]["fmnist-attack"] = dict(rounds=args.attack_rounds,
                    clean_path=str(inputs / "attack-clean.npz"), poison_path=str(inputs / "attack-poison.npz"),
                    steps=120, boost=20.0, poison_batch=6)
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("MKL_NUM_THREADS", "1")
    context = Context(run_id=1, node_id=0, node_config={}, state=RecordDict(),
                      run_config={"aion-source-manifest": str(manifest.resolve())})
    started = time.monotonic()
    workers = args.workers or (4 if len(nodes) > 32 else None)
    grid_factory = ProcessGrid(nodes) if workers is None else PooledProcessGrid(nodes, workers)
    try:
        with grid_factory as grid:
            app(grid, context)
    except ProtocolError:
        if "aion-source-failure" in context.state:
            (args.output / "failure.json").write_bytes(context.state["aion-source-failure"]["failure"])
        raise
    result = json.loads(context.state["aion-source-result"]["result"])
    result["runtime_seconds"] = time.monotonic() - started
    result["local_transport"] = "process-grid" if workers is None else "pooled-process-grid"
    result["local_workers"] = len(nodes) if workers is None else workers
    if args.workload == "fmnist":
        from .fmnist import evaluate, reference_vector, attack_success_rate
        with np.load(inputs / "test.npz", allow_pickle=False) as test:
            result["curve"] = [dict(round=entry["round"], **evaluate(np.asarray(entry["model"]),
                reference_vector(inputs / "reference.npz"), test["x"], test["y"]))
                               for entry in result["history"]]
        if args.attack_clients:
            with np.load(inputs / "poison-test.npz", allow_pickle=False) as poison:
                for entry, row in zip(result["history"], result["curve"], strict=True):
                    row["attack_success_rate"] = attack_success_rate(np.asarray(entry["model"]),
                        reference_vector(inputs / "reference.npz"), poison["x"])
    (args.output / "results.json").write_bytes(canonical(result))
    print(json.dumps(dict(rounds=len(result["history"]),
        key_share_deliveries=result["key_share_deliveries"],
        mask_share_deliveries=result["mask_share_deliveries"],
        source_bft_committed=result["source_bft_committed"], scope=result["scope"]), indent=2))


if __name__ == "__main__":
    cli()

"""Simulation-only provisioning adapter; no physical key isolation is claimed.

The AION handler never offers a plaintext-update endpoint. Plaintext controls
are separately staged FABs using plain_app, with fresh model trajectories.
"""

import json
import time
from functools import lru_cache
from pathlib import Path

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp
from flwr.serverapp import ServerApp

from .client_app import handle, payload, records
from .crypto import ProtocolError, canonical, digest
from .protocol import Parameters
from .workflow import AionWorkflow

client_app = ClientApp()
plain_app = ClientApp()
server_app = ServerApp()


@lru_cache(maxsize=64)
def _read_public_json(path: str):
    return json.loads(Path(path).read_text())


def settings(context, case):
    root = Path(str(context.run_config["provision-dir"]))
    catalog = _read_public_json(str(root / "catalog.json"))
    partition = context.node_config.get("partition-id")
    if type(partition) is not int or case not in catalog or str(partition) not in catalog[case]:
        raise ProtocolError("Unprovisioned simulation identity/case")
    node = catalog[case][str(partition)]
    manifest = _read_public_json(node["aion-manifest"])
    if manifest.get("research-mode") is not True:
        raise ProtocolError("Research opt-in required")
    p = Parameters.from_dict(manifest["parameters"])
    if (context.node_config.get("num-partitions") != len(p.clients) + len(p.aggregators)
            or not 0 <= partition < len(p.clients) + len(p.aggregators)):
        raise ProtocolError("Flower partition count differs from AION roster")
    return node, manifest


@client_app.query("aion")
def secure(message, context):
    request = payload(message)
    node, _ = settings(context, request["runtime-case"])
    local = Context(context.run_id, context.node_id, node, context.state, context.run_config)
    return handle(message, local)


@plain_app.query("identity")
def identity(message, context):
    case = message.content["config"]["case"]
    node, manifest = settings(context, case)
    p = Parameters.from_dict(manifest["parameters"])
    index = context.node_config["partition-id"]
    return Message(RecordDict({"config": ConfigRecord({"partition": index,
        "name": (p.clients + p.aggregators)[index], "case": case})}), reply_to=message)


@plain_app.train()
def plaintext(message, context):
    cfg = message.content["config"]
    node, manifest = settings(context, cfg["case"])
    p = Parameters.from_dict(manifest["parameters"])
    index = context.node_config["partition-id"]
    if index >= len(p.clients):
        raise ProtocolError("Aggregator cannot train")
    offset, = message.content["model"].to_numpy_ndarrays()
    if "fmnist-shard" in node:
        from .fmnist import FmnistTrainer
        trainer = FmnistTrainer(node["fmnist-shard"], node["fmnist-reference"],
                                seed=int(node.get("fmnist-seed", 1)),
                                epochs=int(node.get("fmnist-epochs", 2)),
                                batch_size=int(node.get("fmnist-batch-size", 64)),
                                device=str(node.get("fmnist-device", "cpu")),
                              attack=node.get("fmnist-attack"),
                              sampling_policy=node.get("fmnist-sampling-policy", "legacy"))
        delta = trainer(offset, index, p.learning_rate, cfg["round"])
        meta = trainer.meta
    elif "endpoint-shard" in node:
        from .endpoint_aion import EndpointTrainer
        trainer = EndpointTrainer(node["endpoint-shard"], node["endpoint-seed"], node["endpoint-epochs"],
                                  node["endpoint-batch-size"], node["endpoint-device"])
        delta = trainer(offset, index, p.learning_rate, cfg["round"])
        meta = trainer.meta
    else:
        from .task import local_delta
        delta, meta = local_delta(offset, index, p.learning_rate), {}
    return Message(RecordDict({"delta": ArrayRecord([delta]), "config": ConfigRecord({
        "case": cfg["case"], "round": cfg["round"], "partition": index, "meta": json.dumps(meta)})}), reply_to=message)


class RuntimeWorkflow(AionWorkflow):
    def __init__(self, *args, case, scenario="clean", mgf_seed=0, author_mgf=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.case, self.scenario, self.trace = case, scenario, []
        self.oracle_selector = None
        self.oracle_selections = []
        self.oracle_max_classifier_error = 0.0
        if self.p.oracle_mgf:
            from .fmnist_artifact_mgf import ArtifactMGF, AuthorArtifactMGF
            selector_type = AuthorArtifactMGF if author_mgf else ArtifactMGF
            self.oracle_selector = selector_type(seed=mgf_seed)

    def oracle_filter(self, updates, current, round_id):
        from .fmnist_artifact_mgf import SHPRG_Q, AuthorArtifactMGF
        selector = self.oracle_selector
        cohort = [update["sender"] for update in updates]
        plain = np.stack([np.asarray(update["body"]["oracle_classifier"], dtype=np.float32)
                          for update in updates])
        if isinstance(selector, AuthorArtifactMGF):
            masked, mask_linf = selector.mask_projection(plain)
        else:
            amplitude = selector.mask_weight * selector.previous_linf
            seeds = [selector.random.randint(0, SHPRG_Q - 1) for _ in updates]
            masks = np.stack([selector._mask(seed, amplitude) for seed in seeds]).astype(np.float32)
            masked = plain + masks
            mask_linf = float(np.max(np.sum(masks, axis=0, dtype=np.float64)))
        chosen, trace = selector.select_masked(masked, mask_linf, round_id)
        selected = [updates[index] for index in chosen]
        if isinstance(selector, AuthorArtifactMGF):
            import torch
            expected_classifier = torch.as_tensor(plain[chosen], dtype=torch.float32).mean(dim=0).numpy().astype(np.float64)
        else:
            expected_classifier = np.mean(plain[chosen], axis=0, dtype=np.float32).astype(np.float64)
        self._oracle_pending = {"round": round_id, "cohort": cohort,
                                "selected": [cohort[index] for index in chosen],
                                "expected_classifier": expected_classifier,
                                "trace": trace}
        chosen_by_name = {update["sender"]: update for update in selected}
        return [chosen_by_name[name] for name in self.p.clients if name in chosen_by_name]

    def oracle_observe(self, previous, result, round_id):
        from .fmnist_artifact_mgf import CLASSIFIER_WEIGHT
        pending = self._oracle_pending
        if pending["round"] != round_id:
            raise ProtocolError("oracle MGF state differs from certified round")
        delta = np.asarray(result["body"]["model"]) - np.asarray(previous["body"]["model"])
        error = float(np.max(np.abs(delta[CLASSIFIER_WEIGHT] - pending["expected_classifier"])))
        if error > 2 / self.p.codec.scale:
            raise ProtocolError("oracle classifier differs from selected ASR aggregate")
        self.oracle_max_classifier_error = max(self.oracle_max_classifier_error, error)
        trace = pending["trace"]
        trace.update(self.oracle_selector.observe_aggregate(
            delta, trace["mask_linf"], trace["bound"], round_id))
        self.oracle_selections.append({"round": round_id, "cohort": pending["cohort"],
                                       "selected": pending["selected"],
                                       **{key: value for key, value in trace.items()
                                          if key != "selected_indices"}})

    def _send(self, grid, node_ids, request):
        started = time.perf_counter()
        result = super()._send(grid, node_ids, {**request, "runtime-case": self.case})
        self.trace.append({"action": request["action"], "requests": len(node_ids), "replies": len(result),
                           "seconds": time.perf_counter() - started})
        return result

    def call(self, grid, names, action, **kwargs):
        # Explicit response/request suppression, not a real crash or network timeout.
        if self.scenario == "missing-aggregator":
            names = tuple(n for n in names if n != self.p.aggregators[-1])
        if self.scenario == "client-dropout" and action == "train":
            names = names[:-1]
        if self.scenario == "tampered-model" and action == "train":
            import copy
            kwargs = copy.deepcopy(kwargs)
            kwargs["model"]["body"]["model"][0] += 1
        result = super().call(grid, names, action, **kwargs)
        if self.scenario == "retry" and action in ("enroll", "train", "commit"):
            if super().call(grid, names, action, **kwargs) != result:
                raise ProtocolError("Retry changed signed response")
        if action == "commit":
            print(f"AION_RUNTIME {self.case} committed round={kwargs['model']['body']['round']}", flush=True)
        return result


def clear_run(grid, context, case, p, mode):
    if mode not in ("quantized", "float", "avg", "mgf"):
        raise ProtocolError("Unknown plaintext control mode")
    timeout = float(context.run_config["timeout"])
    schedule_path = context.run_config.get("participation-schedule")
    schedule = json.loads(Path(str(schedule_path)).read_text()) if schedule_path else None
    if schedule is not None and (not isinstance(schedule, dict) or
                                 set(schedule) != {str(i) for i in range(1, int(context.run_config["rounds"]) + 1)}):
        raise ProtocolError("Plaintext participation schedule must cover every round")
    selector = None
    if mode == "mgf":
        if p.dimension != 61706:
            raise ProtocolError("Artifact MGF control requires the FMNIST LeNet5 dimension")
        from .fmnist_artifact_mgf import ArtifactMGF, AuthorArtifactMGF
        selector_type = AuthorArtifactMGF if context.run_config.get("author-mgf", False) else ArtifactMGF
        selector = selector_type(seed=int(context.run_config.get("mgf-seed", 0)))
    party_count = len(p.clients) + len(p.aggregators)
    nodes = list(grid.get_node_ids())
    replies = list(grid.send_and_receive([Message(RecordDict({"config": ConfigRecord({"case": case})}),
        dst_node_id=n, message_type="query.identity", ttl=timeout) for n in nodes], timeout=timeout))
    mapped = {}
    for reply in replies:
        if reply.has_error():
            raise ProtocolError("Identity query failed")
        c = reply.content["config"]
        i = c["partition"]
        if (i in mapped or c["case"] != case or not 0 <= i < party_count
                or c["name"] != (p.clients + p.aggregators)[i]
                or reply.metadata.src_node_id not in nodes):
            raise ProtocolError("Invalid simulation identity")
        mapped[i] = reply.metadata.src_node_id
    if len(mapped) != party_count or len(set(mapped.values())) != party_count:
        raise ProtocolError("Incomplete identity mapping")
    weights, history, totals, meta, selections = np.zeros(p.dimension), [np.zeros(p.dimension)], [], [], []
    for round_id in range(1, int(context.run_config["rounds"]) + 1):
        if schedule is None:
            selected = list(range(len(p.clients)))
        else:
            names = schedule[str(round_id)]
            if (not isinstance(names, list) or len(names) < 2 or len(set(names)) != len(names)
                    or any(name not in p.clients for name in names)):
                raise ProtocolError("Invalid plaintext cohort")
            selected = [p.clients.index(name) for name in names]
        messages = [Message(RecordDict({"model": ArrayRecord([weights]), "config": ConfigRecord({
            "case": case, "round": round_id})}), dst_node_id=mapped[i], message_type="train", ttl=timeout)
            for i in selected]
        replies = list(grid.send_and_receive(messages, timeout=timeout))
        updates = {}
        for reply in replies:
            if reply.has_error():
                raise ProtocolError("Plaintext training failed")
            c = reply.content["config"]
            i = c["partition"]
            if (i in updates or i not in selected or c["case"] != case or c["round"] != round_id
                    or reply.metadata.src_node_id != mapped[i]):
                raise ProtocolError("Wrong plaintext response")
            delta, = reply.content["delta"].to_numpy_ndarrays()
            if delta.shape != weights.shape or not np.isfinite(delta).all():
                raise ProtocolError("Invalid delta")
            updates[i] = delta
            meta.append(json.loads(c["meta"]))
        if len(updates) != len(selected):
            raise ProtocolError("Incomplete cohort")
        ordered = [updates[i] for i in selected]
        if mode == "quantized":
            total = [sum(v) for v in zip(*(p.codec.encode(d) for d in ordered))]
            totals.append(total)
            weights = np.asarray([w + x / (p.codec.scale * len(selected)) for w, x in zip(weights, total)])
        elif mode == "mgf":
            mean, trace = selector.aggregate(np.stack(ordered), round_id)
            weights = weights + mean
            selections.append({"round": round_id, "cohort": [p.clients[i] for i in selected],
                               "selected": [p.clients[selected[i]] for i in trace.pop("selected_indices")],
                               **trace})
        else:
            weights = weights + np.mean(ordered, axis=0)
        history.append(weights.copy())
        print(f"AION_CONTROL {case} {mode} round={round_id}", flush=True)
    return history, totals, meta, selections


@server_app.main()
def main(grid, context):
    cfg = context.run_config
    catalog = json.loads((Path(cfg["provision-dir"]) / "catalog.json").read_text())
    out = Path(cfg["output-dir"]) / f"run-{context.run_id}"
    out.mkdir(parents=True, exist_ok=False)
    mode, cases = cfg["mode"], []
    for case, nodes in catalog.items():
        manifest = json.loads(Path(nodes["0"]["aion-manifest"]).read_text())
        p = Parameters.from_dict(manifest["parameters"])
        scenario = case.split("--")[1]
        row = {"case": case, "task": p.task, "mode": mode, "scenario": scenario}
        started = time.perf_counter()
        workflow = None
        try:
            if mode in ("aion", "aion_mgf_oracle", "aion_mgf_beta"):
                schedule_path = cfg.get("participation-schedule")
                schedule = json.loads(Path(str(schedule_path)).read_text()) if schedule_path else None
                workflow = RuntimeWorkflow(p, manifest["registry"], case=case, scenario=scenario,
                                           mgf_seed=int(cfg.get("mgf-seed", 0)),
                                           author_mgf=bool(cfg.get("author-mgf", False)),
                                           timeout=float(cfg["timeout"]), participation_schedule=schedule)
                certificates = workflow.run(grid, int(cfg["rounds"]))
                history = [c["body"]["model"] for c in certificates]
                (out / f"{case}-certificates.json").write_bytes(canonical(certificates))
                row["certificate_trace_sha256"] = digest(certificates)
                row["certificates"] = [{"round": c["body"]["round"], "digest": digest(c["body"]),
                                        "roster_digest": c["body"].get("roster"),
                                        "signers": [v["sender"] for v in c["votes"]],
                                        "hotstuff_stage": c.get("hotstuff", {}).get("body", {}).get("stage")}
                                       for c in certificates]
                row["certified_rosters"] = [workflow.certified_rosters[r]
                                            for r in range(1, int(cfg["rounds"]) + 1)]
                if p.oracle_mgf:
                    row["selections"] = workflow.oracle_selections
                    row["oracle_max_classifier_error"] = workflow.oracle_max_classifier_error
                elif p.mgf_enabled:
                    row["selections"] = [
                        {"round": round_id, "selected": roster["body"]["members"],
                         "selected_count": len(roster["body"]["members"]),
                         **roster["body"].get("mgf_selection", {})}
                        for round_id, roster in workflow.certified_rosters.items()]
            else:
                history, totals, meta, selections = clear_run(grid, context, case, p, mode)
                row.update(integer_totals=totals, training_meta=meta, selections=selections)
            np.savez_compressed(out / f"{case}-models.npz", offsets=np.asarray(history))
            row["status"] = "completed"
        except ProtocolError:
            if cfg["workload"] != "synthetic" or scenario not in ("client-dropout", "tampered-model"):
                raise
            row["status"] = "expected-abort"
        row["seconds"] = time.perf_counter() - started
        if workflow:
            row["trace"] = workflow.trace
        cases.append(row)
        with (out / f"{case}.json").open("x") as stream:
            json.dump(row, stream, indent=2, allow_nan=False)
    with (out / "results.json").open("x") as stream:
        json.dump({"run_id": context.run_id, "config": dict(cfg), "cases": cases}, stream, indent=2, allow_nan=False)

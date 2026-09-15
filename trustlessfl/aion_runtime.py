"""Simulation-only provisioning adapter; no physical key isolation is claimed.

The AION handler never offers a plaintext-update endpoint. Plaintext controls
are separately staged FABs using plain_app, with fresh model trajectories.
"""

import json
import time
from pathlib import Path

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp
from flwr.serverapp import ServerApp

from .client_app import handle, payload, records
from .crypto import ProtocolError, digest
from .protocol import Parameters
from .workflow import AionWorkflow

client_app = ClientApp()
plain_app = ClientApp()
server_app = ServerApp()


def settings(context, case):
    root = Path(str(context.run_config["provision-dir"]))
    catalog = json.loads((root / "catalog.json").read_text())
    partition = context.node_config.get("partition-id")
    if (type(partition) is not int or context.node_config.get("num-partitions") != 12
            or not 0 <= partition < 12 or case not in catalog):
        raise ProtocolError("Unprovisioned simulation identity/case")
    node = catalog[case][str(partition)]
    manifest = json.loads(Path(node["aion-manifest"]).read_text())
    if manifest.get("research-mode") is not True:
        raise ProtocolError("Research opt-in required")
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
    if "endpoint-shard" in node:
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
    def __init__(self, *args, case, scenario="clean", **kwargs):
        super().__init__(*args, **kwargs)
        self.case, self.scenario, self.trace = case, scenario, []

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
    timeout = float(context.run_config["timeout"])
    nodes = list(grid.get_node_ids())
    replies = list(grid.send_and_receive([Message(RecordDict({"config": ConfigRecord({"case": case})}),
        dst_node_id=n, message_type="query.identity", ttl=timeout) for n in nodes], timeout=timeout))
    mapped = {}
    for reply in replies:
        if reply.has_error():
            raise ProtocolError("Identity query failed")
        c = reply.content["config"]
        i = c["partition"]
        if (i in mapped or c["case"] != case or not 0 <= i < 12
                or c["name"] != (p.clients + p.aggregators)[i]
                or reply.metadata.src_node_id not in nodes):
            raise ProtocolError("Invalid simulation identity")
        mapped[i] = reply.metadata.src_node_id
    if len(mapped) != 12 or len(set(mapped.values())) != 12:
        raise ProtocolError("Incomplete identity mapping")
    weights, history, totals, meta = np.zeros(p.dimension), [np.zeros(p.dimension)], [], []
    for round_id in range(1, int(context.run_config["rounds"]) + 1):
        messages = [Message(RecordDict({"model": ArrayRecord([weights]), "config": ConfigRecord({
            "case": case, "round": round_id})}), dst_node_id=mapped[i], message_type="train", ttl=timeout)
            for i in range(len(p.clients))]
        replies = list(grid.send_and_receive(messages, timeout=timeout))
        updates = {}
        for reply in replies:
            if reply.has_error():
                raise ProtocolError("Plaintext training failed")
            c = reply.content["config"]
            i = c["partition"]
            if (i in updates or not 0 <= i < len(p.clients) or c["case"] != case or c["round"] != round_id
                    or reply.metadata.src_node_id != mapped[i]):
                raise ProtocolError("Wrong plaintext response")
            delta, = reply.content["delta"].to_numpy_ndarrays()
            if delta.shape != weights.shape or not np.isfinite(delta).all():
                raise ProtocolError("Invalid delta")
            updates[i] = delta
            meta.append(json.loads(c["meta"]))
        if len(updates) != len(p.clients):
            raise ProtocolError("Incomplete cohort")
        ordered = [updates[i] for i in range(len(p.clients))]
        if mode == "quantized":
            total = [sum(v) for v in zip(*(p.codec.encode(d) for d in ordered))]
            totals.append(total)
            weights = np.asarray([w + x / (p.codec.scale * len(p.clients)) for w, x in zip(weights, total)])
        else:
            weights = weights + np.mean(ordered, axis=0)
        history.append(weights.copy())
        print(f"AION_CONTROL {case} {mode} round={round_id}", flush=True)
    return history, totals, meta


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
            if mode == "aion":
                workflow = RuntimeWorkflow(p, manifest["registry"], case=case, scenario=scenario, timeout=float(cfg["timeout"]))
                certificates = workflow.run(grid, int(cfg["rounds"]))
                history = [c["body"]["model"] for c in certificates]
                row["certificates"] = [{"round": c["body"]["round"], "digest": digest(c["body"]),
                                        "signers": [v["sender"] for v in c["votes"]]} for c in certificates]
            else:
                history, totals, meta = clear_run(grid, context, case, p, mode)
                row.update(integer_totals=totals, training_meta=meta)
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

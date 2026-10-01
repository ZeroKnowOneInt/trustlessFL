"""Measure the existing Flower apps, with optional transport fault injection.

Run with: python -m experiments.run_aion --output docs/experiments/aion-2026-09-12
No private keys, shares, masked updates or certificates are written to results.
The adversarial harness alone loads the designated malicious party's key.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import statistics
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from flwr.app import Context, Message, RecordDict

from trustlessfl.client_app import payload, records
from trustlessfl.crypto import Identity, ORDER, ProtocolError, canonical
from trustlessfl.demo import provision
from trustlessfl.local_grid import PooledProcessGrid, ProcessGrid
from trustlessfl.numeric import OUTPUT_MODULUS
from trustlessfl.protocol import Parameters
from trustlessfl.server_app import app
from trustlessfl.task import local_delta, loss


@dataclass(frozen=True)
class Case:
    name: str
    clients: int = 4
    aggregators: int = 4
    faults: int = 1
    dimension: int = 8
    rounds: int = 5
    learning_rate: float = 0.01
    attack: str = "none"


class ObservedGrid(ProcessGrid):
    """Count canonical JSON payload bytes, not TCP/protobuf wire overhead.

    Dropped requests simulate immediate suppression, NOT a timeout experiment.
    """

    def __init__(self, nodes: dict, case: Case, p: Parameters, workers: int | None = None):
        self.case, self.parameters = case, p
        self._pooled = workers is not None
        self.events: list[dict] = []
        self.occurrences: dict[str, int] = {}
        self.last_committed_round = 0
        self.cached_update = None
        self.attacks_injected = 0
        self.malicious = None
        target = None
        if case.attack in {"bad_share", "bad_result"}:
            target = case.clients + 1
        elif case.attack == "signed_poison":
            target = 1
        if target is not None:
            self.malicious = Identity.from_private(json.loads(Path(nodes[target]["aion-identity"]).read_text()))
        if self._pooled:
            PooledProcessGrid.__init__(self, nodes, workers)
        else:
            super().__init__(nodes)

    def get_node_ids(self):
        return PooledProcessGrid.get_node_ids(self) if self._pooled else super().get_node_ids()

    def close(self):
        if self._pooled:
            PooledProcessGrid.close(self)
        else:
            super().close()

    def send_and_receive(self, messages, *, timeout=None):
        messages = list(messages)
        if not messages:
            return
        action = payload(messages[0])["action"]
        occurrence = self.occurrences.get(action, 0) + 1
        self.occurrences[action] = occurrence
        forwarded = []
        event = {"action": action, "occurrence": occurrence,
                 "attempted_requests": len(messages), "requests": 0, "replies": 0,
                 "request_payload_bytes": 0, "reply_payload_bytes": 0, "error_replies": 0}
        for message in messages:
            node = message.metadata.dst_node_id
            attack = self.case.attack
            if attack == "client_dropout" and action == "train" and occurrence == 2 and node == 1:
                self.attacks_injected += 1
                continue
            missing = 1 if attack == "one_aggregator_down" else 2 if attack == "two_aggregators_down" else 0
            if missing and action in {"prepare", "share", "finalize", "commit"} and occurrence >= 2:
                if self.case.clients < node <= self.case.clients + missing:
                    self.attacks_injected += 1
                    continue
            if attack == "server_model_tamper" and action == "train" and occurrence == 2 and node == 1:
                request = payload(message)
                request["model"]["body"]["model"][0] += 1.0
                message = Message(records(request), dst_node_id=node,
                                  message_type=message.metadata.message_type,
                                  group_id=message.metadata.group_id, ttl=message.metadata.ttl)
                self.attacks_injected += 1
            forwarded.append(message)
            event["requests"] += 1
            event["request_payload_bytes"] += len(canonical(payload(message)))
        start = time.perf_counter()
        try:
            source = (PooledProcessGrid.send_and_receive(self, forwarded, timeout=timeout)
                      if self._pooled else super().send_and_receive(forwarded, timeout=timeout))
            for reply in source:
                if reply.has_error():
                    event["error_replies"] += 1
                else:
                    envelope = payload(reply)
                    name = envelope["sender"]
                    attack = self.case.attack
                    changed = False
                    if action == "train" and name == "client-0":
                        if occurrence == 1:
                            self.cached_update = copy.deepcopy(envelope)
                        if occurrence == 2 and attack == "replayed_update":
                            envelope = copy.deepcopy(self.cached_update)
                            changed = True
                        if occurrence == 2 and attack == "signed_poison":
                            # Correct mask, arbitrary but in-range model delta: +20.
                            shift = 20 * self.parameters.codec.scale * self.parameters.codec.padding
                            vector = envelope["body"]["vector"]
                            vector[0] = (vector[0] + shift) % OUTPUT_MODULUS
                            envelope = self.malicious.sign(envelope["body"])
                            changed = True
                    if name == "aggregator-0" and occurrence == 2:
                        if action == "share" and attack == "bad_share":
                            envelope["body"]["value"] = (envelope["body"]["value"] + 1) % ORDER
                            envelope = self.malicious.sign(envelope["body"])
                            changed = True
                        if action == "finalize" and attack == "bad_result":
                            envelope["body"]["model"][0] += 1.0
                            envelope = self.malicious.sign(envelope["body"])
                            changed = True
                    if changed:
                        self.attacks_injected += 1
                        reply = Message(content=records(envelope), metadata=reply.metadata)
                    event["reply_payload_bytes"] += len(canonical(envelope))
                event["replies"] += 1
                yield reply
        finally:
            event["seconds"] = time.perf_counter() - start
            self.events.append(event)
            if action == "commit" and event["replies"] - event["error_replies"] >= self.parameters.quorum:
                self.last_committed_round = occurrence


def baseline(p: Parameters, rounds: int, quantized: bool) -> tuple[list[np.ndarray], float]:
    models = [np.zeros(p.dimension)]
    start = time.perf_counter()
    for _ in range(rounds):
        deltas = [local_delta(models[-1], i, p.learning_rate) for i in range(len(p.clients))]
        if quantized:
            mean = np.sum([p.codec.encode(delta) for delta in deltas], axis=0) / (len(p.clients) * p.codec.scale)
        else:
            mean = np.mean(deltas, axis=0)
        models.append(models[-1] + mean)
    return models, time.perf_counter() - start


def heldout_loss(weights: np.ndarray, clients: int) -> float:
    """Independent synthetic evaluation samples from each silo's distribution."""
    errors = []
    for partition in range(clients):
        rng = np.random.default_rng(50000 + partition)
        x = rng.normal(loc=partition * 0.1, size=(256, len(weights)))
        y = x @ np.linspace(0.2, 0.8, len(weights)) + rng.normal(scale=0.01, size=256)
        errors.append(float(np.mean((x @ weights - y)**2)))
    return float(np.mean(errors))


def run_case(case: Case, repeat: int) -> dict:
    p = Parameters(uuid.uuid4().hex,
                   tuple(f"client-{i}" for i in range(case.clients)),
                   tuple(f"aggregator-{i}" for i in range(case.aggregators)),
                   faults=case.faults, dimension=case.dimension, learning_rate=case.learning_rate)
    reference, baseline_time = baseline(p, case.rounds, True)
    unquantized, _ = baseline(p, case.rounds, False)
    result = {"case": asdict(case), "repeat": repeat, "baseline_compute_seconds": baseline_time,
              "status": "completed", "abort_reason": None}
    with tempfile.TemporaryDirectory(prefix="aion-experiment-") as temporary:
        manifest, nodes = provision(Path(temporary) / "identities", p)
        context = Context(1, 0, {}, RecordDict(), {"aion-manifest": str(manifest),
                          "research-mode": True, "num-server-rounds": case.rounds, "timeout": 60.0})
        start = time.perf_counter()
        with ObservedGrid(nodes, case, p) as grid:
            protocol_start = time.perf_counter()
            try:
                app(grid, context)
            except ProtocolError as exc:
                result["status"], result["abort_reason"] = "aborted", str(exc)
            result["protocol_seconds"] = time.perf_counter() - protocol_start
            result["last_committed_round"] = grid.last_committed_round
            result["attacks_injected"] = grid.attacks_injected
            result["events"] = grid.events
        result["wall_seconds"] = time.perf_counter() - start
    result["payload_bytes"] = sum(e["request_payload_bytes"] + e["reply_payload_bytes"] for e in result["events"])
    result["messages"] = sum(e["requests"] + e["replies"] for e in result["events"])
    result["round_call_seconds"] = [sum(e["seconds"] for e in result["events"]
                                       if e["action"] in {"train", "prepare", "share", "finalize", "commit"}
                                       and e["occurrence"] == r) for r in range(1, grid.last_committed_round + 1)]
    if result["status"] == "completed":
        history = json.loads(context.state["aion-result"]["history"])
        models = [np.asarray(h["body"]["model"]) for h in history]
        result["loss"] = [loss(model, case.clients) for model in models]
        result["reference_loss"] = [loss(model, case.clients) for model in reference]
        result["unquantized_loss"] = [loss(model, case.clients) for model in unquantized]
        result["max_abs_error_vs_fixed_point"] = max(float(np.max(np.abs(a-b))) for a, b in zip(models, reference, strict=True))
        result["max_abs_error_vs_float"] = max(float(np.max(np.abs(a-b))) for a, b in zip(models, unquantized, strict=True))
        result["loss_monotone"] = all(b <= a for a, b in zip(result["loss"], result["loss"][1:]))
        result["heldout_initial_loss"] = heldout_loss(models[0], case.clients)
        result["heldout_final_loss"] = heldout_loss(models[-1], case.clients)
        result["heldout_reference_final_loss"] = heldout_loss(reference[-1], case.clients)
        result["final_model"] = models[-1].tolist()
    expected_abort = case.attack in {"two_aggregators_down", "client_dropout", "server_model_tamper", "replayed_update"}
    result["expected_status"] = "aborted" if expected_abort else "completed"
    result["expectation_met"] = result["status"] == result["expected_status"]
    if case.attack != "none":
        result["expectation_met"] &= result["attacks_injected"] > 0
    if expected_abort:
        result["expectation_met"] &= result["last_committed_round"] == 1
    elif result["status"] == "completed":
        if case.attack == "signed_poison":
            result["expectation_met"] &= result["max_abs_error_vs_fixed_point"] > 0
        else:
            result["expectation_met"] &= result["max_abs_error_vs_fixed_point"] == 0
    return result


def metadata() -> dict:
    sources = sorted(Path("trustlessfl").glob("*.py")) + [Path(__file__)]
    return {"started_utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
            "python": platform.python_version(), "logical_cpus": os.cpu_count(),
            "packages": {name: importlib.metadata.version(name) for name in ["flwr", "numpy", "cryptography"]},
            "thread_environment": {name: os.environ.get(name) for name in ["OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"]},
            "source_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
            "transport": "ProcessGrid / Flower protobuf / local multiprocessing pipes",
            "timing": "sequential trials; wall includes process startup/shutdown, excludes provisioning and baseline; no warmup",
            "payload": "canonical JSON request+successful reply content, includes model and encrypted shares, excludes protobuf/TCP/error payload overhead",
            "faults": "suppression is immediate, not a simulated network timeout",
            "data": "synthetic non-IID least-squares; training 32 samples/client (seed 1000+partition); held-out 256 samples/client (seed 50000+partition); fresh crypto keys each trial",
            "loss": "loss arrays measure training MSE; heldout_* fields measure independent synthetic evaluation MSE",
            "expectations": "expected outcomes include successful signed poisoning (a known limitation), not a claim that every attack is defended"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("repeats must be positive")
    args.output.mkdir(parents=True, exist_ok=False)
    result = {"environment": metadata(), "runs": []}
    cases = [Case("clients_2", clients=2), Case("baseline_4"), Case("clients_8", clients=8),
             Case("aggregators_7", aggregators=7, faults=2),
             Case("dimension_128", dimension=128), Case("dimension_1024", dimension=1024),
             Case("convergence_30", rounds=30, learning_rate=0.1)]
    trials = [(case, repeat) for case in cases for repeat in range(1, args.repeats + 1)]
    trials += [(Case(attack, rounds=3, learning_rate=0.1, attack=attack), 1) for attack in [
        "one_aggregator_down", "two_aggregators_down", "client_dropout", "bad_share",
        "bad_result", "server_model_tamper", "replayed_update", "signed_poison"]]
    for index, (case, repeat) in enumerate(trials, 1):
        print(f"[{index}/{len(trials)}] {case.name} repeat={repeat}", flush=True)
        run = run_case(case, repeat)
        result["runs"].append(run)
        (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"  {run['status']}: {run['wall_seconds']:.3f}s, {run['payload_bytes']/1024:.1f} KiB, committed={run['last_committed_round']}", flush=True)
    result["completed_utc"] = datetime.now(timezone.utc).isoformat()
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    with (args.output / "summary.csv").open("w", newline="") as stream:
        fields = ["name", "trials", "clients", "aggregators", "dimension", "rounds", "status",
                  "wall_median_s", "wall_min_s", "wall_max_s", "payload_median_kib", "initial_loss",
                  "final_loss", "clear_final_loss", "max_abs_error_fixed_point", "last_committed_round"]
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        for name in dict.fromkeys(r["case"]["name"] for r in result["runs"]):
            runs = [r for r in result["runs"] if r["case"]["name"] == name]
            first = runs[0]
            row = {key: first["case"][key] for key in ["name", "clients", "aggregators", "dimension", "rounds"]}
            row.update(trials=len(runs), status=",".join(sorted({r["status"] for r in runs})),
                       wall_median_s=statistics.median(r["wall_seconds"] for r in runs),
                       wall_min_s=min(r["wall_seconds"] for r in runs), wall_max_s=max(r["wall_seconds"] for r in runs),
                       payload_median_kib=statistics.median(r["payload_bytes"] for r in runs)/1024,
                       last_committed_round=first["last_committed_round"])
            if "loss" in first:
                row.update(initial_loss=first["loss"][0], final_loss=first["loss"][-1],
                           clear_final_loss=first["reference_loss"][-1],
                           max_abs_error_fixed_point=max(r["max_abs_error_vs_fixed_point"] for r in runs))
            writer.writerow(row)
    print(f"Results: {args.output}", flush=True)
    if not all(run["expectation_met"] for run in result["runs"]):
        raise SystemExit("One or more experiments had an unexpected result; inspect results.json")


if __name__ == "__main__":
    main()

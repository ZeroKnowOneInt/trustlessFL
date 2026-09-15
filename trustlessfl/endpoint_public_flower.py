"""Public training recipe on one official Flower worker; two evaluation protocols."""

import json
from pathlib import Path

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp
from flwr.serverapp import Grid, ServerApp

client_app = ClientApp()
server_app = ServerApp()


def load(root, profile, split):
    with np.load(Path(root) / profile / f"{split}.npz", allow_pickle=False) as data:
        return data["x"], data["y"]


@client_app.train()
def train(message: Message, context: Context):
    from .endpoint_public import fit, evaluate_arrays
    if context.node_config.get("partition-id") != 0 or context.node_config.get("num-partitions") != 1:
        raise ValueError("Expected a single public-data worker")
    cfg = context.run_config
    profile, seed = message.content["config"]["profile"], int(message.content["config"]["seed"])
    if profile not in ("group-holdout", "row-reference"):
        raise ValueError("Invalid profile")
    train_x, train_y = load(cfg["data-dir"], profile, "train")
    val_x, val_y = load(cfg["data-dir"], profile, "validation")
    def progress(row):
        if row["epoch"] == 1 or row["epoch"] % 5 == 0:
            print(f"PUBLIC_ENDPOINT {profile} seed={seed} epoch={row['epoch']} "
                  f"val-F1={row['validation']['macro_f1']:.6f} wait={row['wait']}", flush=True)
    result, initial, best = fit(train_x, train_y, val_x, val_y, seed=seed,
        max_epochs=int(cfg["max-epochs"]), batch_size=int(cfg["batch-size"]), patience=int(cfg["patience"]),
        learning_rate=float(cfg["learning-rate"]), device=str(cfg["device"]), progress=progress)
    # Do not load the independent test until validation-only selection is complete.
    test_x, test_y = load(cfg["data-dir"], profile, "evaluation")
    result["profile"] = profile
    result["evaluation_kind"] = "independent-test" if profile == "group-holdout" else "reused-validation-NOT-independent-test"
    result["evaluation"] = evaluate_arrays(best, test_x, test_y, device=str(cfg["device"]), batch_size=int(cfg["batch-size"]))
    return Message(RecordDict({"initial": ArrayRecord(initial), "best": ArrayRecord(best),
        "result": ConfigRecord({"json": json.dumps(result, allow_nan=False)})}), reply_to=message)


@server_app.main()
def main(grid: Grid, context: Context):
    cfg = context.run_config
    nodes = list(grid.get_node_ids())
    if len(nodes) != 1:
        raise ValueError("Expected one virtual node")
    output = Path(str(cfg["output-dir"])) / f"run-{context.run_id}"
    output.mkdir(parents=True, exist_ok=False)
    cases = []
    for profile in str(cfg["profiles"]).split(","):
        for seed in map(int, str(cfg["seeds"]).split(",")):
            request = Message(RecordDict({"config": ConfigRecord({"profile": profile, "seed": seed})}),
                              dst_node_id=nodes[0], message_type="train")
            replies = list(grid.send_and_receive([request], timeout=float(cfg["timeout"])))
            if len(replies) != 1 or replies[0].metadata.src_node_id != nodes[0]:
                raise ValueError("Missing/incorrect worker reply")
            reply = replies[0]
            if reply.has_error():
                raise RuntimeError(reply.error.reason)
            result = json.loads(reply.content["result"]["json"])
            if result["seed"] != seed or result["profile"] != profile:
                raise ValueError("Wrong seed/profile")
            name = f"{profile}-seed-{seed}"
            for key in ("initial", "best"):
                np.savez_compressed(output / f"{name}-{key}.npz", *reply.content[key].to_numpy_ndarrays())
            with (output / f"{name}.json").open("x") as stream:
                json.dump(result, stream, indent=2, allow_nan=False)
            cases.append(result)
            print(f"PUBLIC_ENDPOINT finished {name} best={result['best_epoch']} "
                  f"eval-F1={result['evaluation']['macro_f1']:.6f}", flush=True)
    with (output / "results.json").open("x") as stream:
        json.dump({"run_id": context.run_id, "config": dict(cfg), "cases": cases,
                   "runtime": "Official Flower Simulation Runtime / Ray", "security": "None"},
                  stream, indent=2, allow_nan=False)

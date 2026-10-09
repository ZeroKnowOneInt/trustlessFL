"""Official Flower simulation entrypoints for the author ASR source port.

partition-id selects an actor configuration, never a shared actor state. Keys
and original VSS shares remain in the per-node Context across Ray worker reuse.
"""

import hashlib
import json
import time
from pathlib import Path

from flwr.app import Context, Error, Message
from flwr.clientapp import ClientApp
from flwr.serverapp import ServerApp

from .aion_source_asr import flower_source_request
from .aion_source_server import AuthorASRWorkflow
from .client_app import payload, records
from .crypto import ProtocolError, canonical
from .paper_dmc import QuantizedLiftError
from .aion_source_aggregate import AggregateValidationError
from .source_paper_numeric import MGFSelectionError
from .source_profiles import SourceProfileError

client_app = ClientApp()
server_app = ServerApp()


def actor_config(context: Context):
    raw = Path(context.run_config["source-node-configs"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != context.run_config["source-node-configs-sha256"]:
        raise ProtocolError("source node catalog changed")
    nodes = json.loads(raw)
    index = context.node_config["partition-id"]
    if (type(index) is not int or not 0 <= index < len(nodes)
            or context.node_config["num-partitions"] != len(nodes)):
        raise ProtocolError("source simulation partition mismatch")
    return nodes[index]


@client_app.query("aion_source_asr")
def handle(message: Message, context: Context):
    try:
        result = flower_source_request(actor_config(context), context.state, payload(message))
        return Message(records(result), reply_to=message)
    except QuantizedLiftError as exc:
        return Message(error=Error(code=400, reason="Author ASR numeric failure: " + exc.code),
                       reply_to=message)
    except AggregateValidationError as exc:
        return Message(error=Error(code=400, reason="Author ASR aggregate validation failure: " + exc.code),
                       reply_to=message)
    except MGFSelectionError as exc:
        return Message(error=Error(code=400, reason="Author ASR MGF selection failure: " + exc.code),
                       reply_to=message)
    except SourceProfileError as exc:
        return Message(error=Error(code=400, reason="Author ASR profile failure: " + exc.code),
                       reply_to=message)
    except (ProtocolError, ValueError, KeyError, TypeError, OverflowError):
        return Message(error=Error(code=400, reason="Author ASR request rejected"), reply_to=message)


def evaluate_result(result, manifest):
    """Evaluation only; not used to select or aggregate clients."""
    if manifest.get("workload") != "fmnist":
        return
    import numpy as np
    import torch
    from .fmnist import evaluate, reference_vector, attack_success_rate
    inputs = Path(manifest["training"]["input_root"])
    expected = manifest["training"].get("evaluation_sha256", {})
    for name, sha in expected.items():
        if hashlib.sha256((inputs / name).read_bytes()).hexdigest() != sha:
            raise ProtocolError("source evaluation inputs changed")
    threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        ref = reference_vector(inputs / "reference.npz")
        with np.load(inputs / "test.npz", allow_pickle=False) as test:
            result["curve"] = [dict(round=e["round"], **evaluate(np.asarray(e["model"]), ref,
                test["x"], test["y"])) for e in result["history"]]
        if manifest["training"]["attack_clients"]:
            with np.load(inputs / "poison-test.npz", allow_pickle=False) as poison:
                for e, row in zip(result["history"], result["curve"], strict=True):
                    row["attack_success_rate"] = attack_success_rate(np.asarray(e["model"]), ref, poison["x"])
    finally:
        torch.set_num_threads(threads)


@server_app.main()
def main(grid, context: Context):
    path = Path(context.run_config["aion-source-manifest"])
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != context.run_config["source-manifest-sha256"]:
        raise ProtocolError("source runtime manifest changed")
    manifest = json.loads(raw)
    if any((path.parent / name).exists() for name in ("results.json", "failure.json")):
        raise ProtocolError("source runtime task already has a terminal record; stage a fresh task")
    started = time.monotonic()
    completed = []
    def progress(round_id, vectors, shares, selection, final):
        completed.append(dict(round=round_id, selected=selection["selected"],
            **({"paper_numeric": final["outbox"][0]["body"]["paper_numeric"]}
               if "paper_numerics" in manifest else {})))
        print(f"Author ASR round {round_id}/{manifest['rounds']} committed; "
              f"selected {len(selection['selected'])} clients", flush=True)
    workflow = AuthorASRWorkflow(manifest, timeout=float(context.run_config.get("timeout", 120)),
                               on_round=progress)
    try:
        result = workflow.run(grid)
    except ProtocolError:
        # Only public categories and previously committed metadata. Never copy
        # exception text, pending masked coordinates, private Contexts or shares.
        failure = dict(status="failed", request=workflow.last_request, category=workflow.failure_code,
            completed_rounds=completed, requested_rounds=manifest["rounds"],
            flower_run_id=context.run_id, transport="official-flower-superlink-ray",
            runtime_seconds=time.monotonic() - started,
            scope="public committed metadata only; failed round not committed")
        with (path.parent / "failure.json").open("xb") as stream:
            stream.write(canonical(failure))
        raise
    result.update(runtime_seconds=time.monotonic() - started, flower_run_id=context.run_id,
                  transport="official-flower-superlink-ray")
    evaluate_result(result, manifest)
    # One fresh stage is one run. Never replace a completed result on rerun.
    with (path.parent / "results.json").open("xb") as stream:
        stream.write(canonical(result))

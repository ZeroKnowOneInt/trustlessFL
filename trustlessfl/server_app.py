"""Flower server holds public registry and certified aggregates only."""

import json
import logging
from pathlib import Path

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context
from flwr.serverapp import Grid, ServerApp

from .crypto import ProtocolError, canonical
from .protocol import Parameters
from .workflow import AionWorkflow

app = ServerApp()


@app.main()
def main(grid: Grid, context: Context) -> None:
    if context.run_config.get("research-mode") is not True:
        raise ProtocolError("research-mode=true is required; HPRF is experimental")
    manifest = json.loads(Path(str(context.run_config["aion-manifest"])).read_text())
    if manifest.get("research-mode") is not True:
        raise ProtocolError("manifest must explicitly permit research mode")
    p = Parameters.from_dict(manifest["parameters"])
    logging.warning("AION-ASR research backend: not suitable for private production data")
    workflow = AionWorkflow(p, manifest["registry"], timeout=float(context.run_config.get("timeout", 30)))
    history = workflow.run(grid, int(context.run_config.get("num-server-rounds", 3)))
    context.state["model"] = ArrayRecord([np.asarray(history[-1]["body"]["model"])])
    context.state["aion-result"] = ConfigRecord({"history": canonical(history), "research-only": True})

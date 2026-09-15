"""Run the Flower apps with independent local actor processes."""

import argparse
import json
import os
import tempfile
import uuid
from dataclasses import asdict
from pathlib import Path

import numpy as np
from flwr.app import Context, RecordDict

from .crypto import Identity, canonical
from .local_grid import ProcessGrid
from .protocol import Parameters
from .server_app import app
from .task import loss


def provision(directory: Path, p: Parameters) -> tuple[Path, dict[int, dict]]:
    """Local test enrollment ceremony; production provisioning is out-of-band.

    Create a NEW directory only. Never overwrite identities or rollback locks.
    Copy each party's private directory only to that party for distributed use.
    """
    directory.mkdir(mode=0o700)
    registry, nodes = {}, {}
    manifest_path = directory / "manifest.json"
    for node_id, name in enumerate(p.clients + p.aggregators, 1):
        identity = Identity.generate(name)
        private_dir = directory / name
        private_dir.mkdir(mode=0o700)
        private_path = private_dir / "identity.json"
        descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(identity.private()))
        registry[name] = identity.public()
        nodes[node_id] = {"aion-manifest": str(manifest_path.resolve()),
                          "aion-identity": str(private_path.resolve())}
    manifest_path.write_bytes(canonical({"research-mode": True, "parameters": asdict(p), "registry": registry}))
    return manifest_path, nodes


def main():
    parser = argparse.ArgumentParser(description="Experimental AION-ASR on Flower; synthetic data only")
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--aggregators", type=int, default=4)
    parser.add_argument("--faults", type=int, default=1)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--dimension", type=int, default=3)
    parser.add_argument("--provision-only", type=Path, help="Create NEW identity directory for a Flower deployment")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("rounds must be positive")
    p = Parameters(uuid.uuid4().hex, tuple(f"client-{i}" for i in range(args.clients)),
                   tuple(f"aggregator-{i}" for i in range(args.aggregators)),
                   faults=args.faults, dimension=args.dimension)
    if args.provision_only:
        manifest_path, _ = provision(args.provision_only.resolve(), p)
        print(f"Research manifest: {manifest_path}")
        return
    with tempfile.TemporaryDirectory(prefix="trustlessfl-aion-") as temporary:
        manifest_path, nodes = provision(Path(temporary) / "identities", p)
        context = Context(run_id=1, node_id=0, node_config={}, state=RecordDict(), run_config={
            "aion-manifest": str(manifest_path), "research-mode": True,
            "num-server-rounds": args.rounds, "timeout": 45.0})
        with ProcessGrid(nodes) as grid:
            app(grid, context)
        history = json.loads(context.state["aion-result"]["history"])
        print(json.dumps({"backend": "aion-asr-research-v1", "research_only": True,
                          "clients": args.clients, "independent_aggregator_processes": args.aggregators,
                          "rounds": args.rounds,
                          "loss": [loss(np.asarray(h["body"]["model"]), args.clients) for h in history],
                          "final_model": history[-1]["body"]["model"]}, indent=2))


if __name__ == "__main__":
    main()

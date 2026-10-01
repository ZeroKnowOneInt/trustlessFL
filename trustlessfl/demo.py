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
    parser.add_argument("--privacy-group-size", type=int, default=0,
                        help="Enable disjoint all-or-nothing client groups (0 keeps the fixed cohort)")
    parser.add_argument("--ema-weight", type=float, default=0.0,
                        help="Scale a complete group's one-round-late mean delta; requires privacy groups")
    parser.add_argument("--mask-backend", choices=("artifact", "lwe-reference", "lwe-192-reference", "aion-original"),
                        default="artifact")
    parser.add_argument("--original-hprf-dir", type=Path,
                        help="Author HPRF directory; required for aion-original, files are read-only")
    parser.add_argument("--hprf-width", type=int, default=8,
                        help="Experimental binary-matrix HPRF key width; no security level is implied")
    parser.add_argument("--hprf-input-bits", type=int, choices=(32, 128), default=None,
                        help="LWE defaults to collision-free 128; 32 explicitly preserves legacy research tasks")
    parser.add_argument("--leader-views", action="store_true",
                        help="Use signed aggregator leader failover for roster/model proposals")
    parser.add_argument("--hotstuff", action="store_true",
                        help="Use the research Basic HotStuff voting core (pacemaker incomplete)")
    parser.add_argument("--mgf-beta", default="",
                        help="Enable bounded-mask MGF; requires the three bootstrap values below")
    parser.add_argument("--mgf-initial-alpha", default="",
                        help="Initial HPRF mask scale for MGF, as a positive decimal string")
    parser.add_argument("--mgf-initial-bound", default="",
                        help="Initial masked-gradient L2 bound, as a positive decimal string")
    parser.add_argument("--mgf-initial-term", default="",
                        help="Public bootstrap norm term for the first evolving bound")
    parser.add_argument("--provision-only", type=Path, help="Create NEW identity directory for a Flower deployment")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("rounds must be positive")
    if args.privacy_group_size and (args.privacy_group_size < 2 or args.clients % args.privacy_group_size):
        parser.error("privacy-group-size must be at least two and divide clients")
    clients = tuple(f"client-{i}" for i in range(args.clients))
    original_setup = ()
    if args.mask_backend == "aion-original":
        if args.original_hprf_dir is None:
            parser.error("aion-original requires --original-hprf-dir")
        from .aion_original_hprf import OriginalAionHPRF
        original_setup = OriginalAionHPRF.from_directory(args.original_hprf_dir).public_setup()
    elif args.original_hprf_dir is not None:
        parser.error("--original-hprf-dir requires --mask-backend aion-original")
    groups = (tuple(clients[i:i + args.privacy_group_size]
                    for i in range(0, len(clients), args.privacy_group_size))
              if args.privacy_group_size else ())
    p = Parameters(uuid.uuid4().hex, clients,
                   tuple(f"aggregator-{i}" for i in range(args.aggregators)),
                   faults=args.faults, dimension=args.dimension,
                   privacy_groups=groups, ema_weight=args.ema_weight,
                   mask_backend=args.mask_backend, hprf_width=args.hprf_width,
                   original_hprf_setup=original_setup,
                   hprf_input_bits=args.hprf_input_bits,
                   leader_views=args.leader_views, hotstuff=args.hotstuff,
                   mgf_beta=args.mgf_beta, mgf_initial_alpha=args.mgf_initial_alpha,
                   mgf_initial_bound=args.mgf_initial_bound,
                   mgf_initial_term=args.mgf_initial_term)
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
        print(json.dumps({"backend": "aion-asr-research-v2", "research_only": True,
                          "clients": args.clients, "independent_aggregator_processes": args.aggregators,
                          "rounds": args.rounds,
                          "loss": [loss(np.asarray(h["body"]["model"]), args.clients) for h in history],
                          "final_model": history[-1]["body"]["model"]}, indent=2))


if __name__ == "__main__":
    main()

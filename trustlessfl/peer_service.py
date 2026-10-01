"""Run the optional aggregator peer handler beside a Flower SuperNode.

This service can reconcile signed client updates and finish a fixed-cohort
round after Flower fails, or recover a durable roster/model proposal. In
leader-view mode it can rotate through the current finite leader chain. It
cannot start new client training or guarantee full HotStuff liveness.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
from pathlib import Path

from .crypto import ProtocolError
from .peer_party import PeerParty


def _addresses(path: Path) -> dict[str, tuple[str, int]]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or any(
        not isinstance(name, str) or not isinstance(address, list) or len(address) != 2
        for name, address in value.items()
    ):
        raise ProtocolError("invalid peer address file")
    return {name: (address[0], address[1]) for name, address in value.items()}


async def serve(args: argparse.Namespace) -> None:
    addresses = _addresses(args.peers)
    loopback = ("127.0.0.1", "::1", "localhost")
    if (args.host not in loopback or any(host not in loopback for host, _ in addresses.values())) \
            and not args.allow_insecure_network:
        raise ProtocolError("non-loopback peer network requires explicit insecure-network opt-in")
    if type(args.port) is not int or not 0 <= args.port < 65536:
        raise ProtocolError("invalid peer listen port")
    node_config = {"aion-manifest": str(args.manifest), "aion-identity": str(args.identity)}
    peer = PeerParty(node_config, addresses, auto_complete=True,
                     recovery_delay=args.recovery_delay)
    try:
        host, port = await peer.start(args.host, args.port)
        print(json.dumps({"ready": True, "name": peer.transport.identity.name,
                          "host": host, "port": port}), flush=True)
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGTERM, stopped.set)
        except NotImplementedError:
            pass
        stop_task = asyncio.create_task(stopped.wait())
        try:
            worker = peer._worker
            if worker is None:
                await stop_task
            else:
                done, _ = await asyncio.wait((stop_task, worker),
                                             return_when=asyncio.FIRST_COMPLETED)
                if worker in done:
                    await worker  # Surface an unexpected recovery failure.
                    raise RuntimeError("peer recovery worker stopped unexpectedly")
        finally:
            stop_task.cancel()
            await asyncio.gather(stop_task, return_exceptions=True)
    finally:
        await peer.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Research-only AION aggregator peer handler")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--peers", required=True, type=Path,
                        help="JSON mapping other aggregator names to [host, port]")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--recovery-delay", type=float, default=5.0,
                        help="Seconds to allow Flower to complete after a durable roster")
    parser.add_argument("--allow-insecure-network", action="store_true",
                        help="Permit non-loopback research transport (application-layer encrypted, not audited)")
    args = parser.parse_args()
    asyncio.run(serve(args))


if __name__ == "__main__":
    main()

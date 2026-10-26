"""DDDNS node: a decentralized network core plus modules, on one asyncio event loop.

    python main.py                       start with the modules enabled in data/config.json
    python main.py --network home        open a saved network straight away (name, number or topic)
    python main.py --headless            no prompt: run as a service (see README.md)
    python main.py --data D:/node2       keep identity and networks somewhere else than data/
    python main.py --host 127.0.0.1      services (DNS, DDNS) only for this machine, not the LAN
    python main.py --upstream 9.9.9.9    where the DNS module forwards names that aren't ours
    python main.py --no-dns --no-ddns    keep a module enabled but don't start its server
    python main.py --classic             the original plain console instead of the terminal

Layout:
    core/          the network with nothing in it: identity, joining, roles, sync, CLI
      sidecar/     Hyperswarm (Node.js): discovery, NAT traversal, encryption, signatures
    modules/       what gives it a purpose; enable/disable with /module
      dns/         the DNS map, delegations, node hostnames, DNS server
      ddns/        dyndns2 endpoint for cameras and routers (needs dns)
      chat/        /dm and /broadcast
    data/          this node's identity, config, log and every network's files
    deploy/        running it as a service (systemd, Windows Task Scheduler)
"""

import argparse
import asyncio
import signal
import sys
from pathlib import Path

from core.controller import DATA, Controller
from core.headless import setup_logging
from core.sidecar_api import SidecarAPI
from core.storage import Config, Identity

DEFAULT_MODULES = ["dns", "ddns", "chat"]


async def run(options: dict) -> int:
    data = Path(options["data"]).expanduser().resolve() if options.get("data") else DATA
    setup_logging(data / "dddns.log", to_stdout=options["headless"])
    identity = Identity(data / "identity.json")
    config = Config(data / "config.json", DEFAULT_MODULES)
    api = SidecarAPI()
    await api.start(identity.seed)
    api.firewall([], [])  # accept nobody until a network is joined

    controller = Controller(identity, api, config, options, saved_networks=data / "saved_networks")
    try:
        # A service manager stops us with SIGTERM: leave the network properly. (Not on
        # Windows, where asyncio can't catch signals; Ctrl+C still works there.)
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, controller.stop)
    except (NotImplementedError, AttributeError):
        pass
    controller.notify(f"modules: {', '.join(controller.modules) or '(none)'}")
    for line in await controller.start_modules():
        controller.notify(line)
    try:
        await controller.run()
    finally:
        await controller.shutdown()  # say goodbye if we're on a network
        await controller.stop_modules()
        await api.close()
        if options["headless"]:
            controller.notify("stopped")
    return controller.exit_code


def main():
    p = argparse.ArgumentParser(description="DDDNS node")
    p.add_argument("--network", metavar="NAME", help="open this saved network at start (its name, number or topic)")
    p.add_argument("--headless", action="store_true",
                   help="no prompt: open the network (--network, or the only saved one) and keep running")
    p.add_argument("--data", metavar="DIR", help="folder for identity, config, log and networks (default: data/)")
    p.add_argument("--host", default="0.0.0.0", help="address module servers listen on (default: all, i.e. the LAN)")
    p.add_argument("--upstream", default="1.1.1.1", help="DNS server for names that aren't ours ('none' to refuse them)")
    p.add_argument("--no-dns", action="store_true", help="don't start the DNS server")
    p.add_argument("--no-ddns", action="store_true", help="don't start the DDNS update endpoint")
    p.add_argument("--classic", action="store_true", help="use the original plain console instead of the terminal")
    try:
        code = asyncio.run(run(vars(p.parse_args())))
    except KeyboardInterrupt:
        code = 0
    sys.exit(code)


if __name__ == "__main__":
    main()

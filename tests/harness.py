"""Test helpers: real nodes (each with its own sidecar and data folder) driven
in-process through the controller, plus small DNS/HTTP clients.

The nodes use the real Hyperswarm DHT, so tests need internet access and take
a few seconds per connection.
"""

import asyncio
import base64
import ipaddress
import shutil
import struct
import tempfile
import time
from pathlib import Path

from core.controller import Controller
from core.sidecar_api import SidecarAPI
from core.storage import Config, Identity

TMP = Path(tempfile.gettempdir()) / "dddns-tests"


class ScriptedConsole:
    """Stands in for the keyboard: answers prompts from a list."""

    def __init__(self):
        self.answers: list[str] = []
        self._empty = 0

    async def input(self, prompt: str = "", secret: bool = False, command: bool = False) -> str:
        """The next scripted answer; once they run out, Enter (an empty line).
        Repeated empty answers end input, so a prompt that insists can't hang a test."""
        if self.answers:
            self._empty = 0
            return self.answers.pop(0)
        self._empty += 1
        if self._empty > 3:
            raise EOFError
        return ""

    def stop(self):
        self.answers.clear()


class Node:
    def __init__(self, base: Path, name: str, modules=("dns", "ddns", "chat"), **options):
        self.name = name
        self.dir = base / name
        self.modules = list(modules)
        self.options = {"host": "127.0.0.1", "no_dns": True, "no_ddns": True, **options}
        self.notes: list[str] = []

    async def start(self) -> "Node":
        self.identity = Identity(self.dir / "identity.json")
        self.api = SidecarAPI()
        await self.api.start(self.identity.seed)
        self.api.firewall([], [])
        config = Config(self.dir / "config.json", self.modules)
        self.ctl = Controller(self.identity, self.api, config, self.options, saved_networks=self.dir / "saved_networks")
        self.ctl.console = ScriptedConsole()
        self.ctl.notify = self.notes.append
        self.startup = await self.ctl.start_modules()
        return self

    @property
    def net(self):
        return self.ctl.net

    def module(self, name):
        return self.ctl.modules[name]

    async def run(self, line: str, *answers: str) -> str:
        self.ctl.console.answers = list(answers)
        return await self.ctl.execute(line)

    async def close(self):
        await self.ctl.shutdown()
        await self.ctl.stop_modules()
        await self.api.close()


async def wait(cond, timeout: float = 60) -> int:
    start = time.time()
    while time.time() - start < timeout:
        try:
            if cond():
                break
        except (AttributeError, KeyError, TypeError):
            pass  # e.g. not on a network yet
        await asyncio.sleep(0.3)
    return round(time.time() - start)


def fresh_dir(name: str) -> Path:
    base = TMP / name
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True)
    return base


async def network_of(base: Path, *names: str, **node_options) -> list[Node]:
    """First node creates 'home', the others join it; returns once all are connected."""
    nodes = []
    first = await Node(base, names[0], **node_options).start()
    await first.run("/create home", names[0].capitalize())
    await asyncio.sleep(6)  # let the creator's announcement reach the DHT
    nodes.append(first)
    for name in names[1:]:
        node = await Node(base, name, **node_options).start()
        await node.run(f"/join {first.net.topic}", name.capitalize())
        nodes.append(node)
    await wait(lambda: all(len(n.net.online) == len(nodes) - 1 for n in nodes), 90)
    return nodes


def dns_entries(node: Node, include_node_names: bool = False) -> dict[str, str]:
    rows = node.module("dns").dns_map.active()
    return {r["hostname"]: r["ip"] for r in rows if include_node_names or not r["hostname"].startswith("n-")}


# --- DNS and HTTP clients ------------------------------------------------------------

def dns_query(qname: str, qtype: int = 1) -> bytes:
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in qname.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", qtype, 1)


def _read_name(data: bytes, pos: int) -> tuple[str, int]:
    """A (possibly compressed) DNS name at pos -> (name, position after it)."""
    labels, end = [], None
    while True:
        length = data[pos]
        if length & 0xC0:
            end = end or pos + 2
            pos = struct.unpack("!H", data[pos:pos + 2])[0] & 0x3FFF
            continue
        pos += 1
        if not length:
            return ".".join(labels), end or pos
        labels.append(data[pos:pos + length].decode())
        pos += length


def _read_records(data: bytes, pos: int, count: int) -> tuple[list, int]:
    """A/AAAA records -> IP strings; SRV records -> (priority, weight, port, target)."""
    out = []
    for _ in range(count):
        _, pos = _read_name(data, pos)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        rdata = data[pos + 10:pos + 10 + rdlen]
        if rtype in (1, 28):
            out.append(str(ipaddress.ip_address(rdata)))
        elif rtype == 33:
            priority, weight, srv_port = struct.unpack("!HHH", rdata[:6])
            out.append((priority, weight, srv_port, _read_name(data, pos + 16)[0]))
        pos += 10 + rdlen
    return out, pos


def parse_reply(data: bytes, with_additional: bool = False):
    _, flags, _, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    _, pos = _read_name(data, 12)
    answers, pos = _read_records(data, pos + 4, ancount)
    rcode = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}.get(flags & 0xF)
    if not with_additional:
        return rcode, answers
    _, pos = _read_records(data, pos, nscount)
    additional, _ = _read_records(data, pos, arcount)
    return rcode, answers, additional


async def udp_ask(port: int, qname: str, qtype: int = 1, with_additional: bool = False):
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    class Reply(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not future.done():
                future.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(Reply, remote_addr=("127.0.0.1", port))
    transport.sendto(dns_query(qname, qtype))
    try:
        return parse_reply(await asyncio.wait_for(future, 5), with_additional)
    finally:
        transport.close()


async def tcp_ask(port: int, qname: str, qtype: int = 1):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    query = dns_query(qname, qtype)
    writer.write(struct.pack("!H", len(query)) + query)
    await writer.drain()
    size = struct.unpack("!H", await reader.readexactly(2))[0]
    data = await reader.readexactly(size)
    writer.close()
    return parse_reply(data)


async def http_get(port: int, path: str, user: str | None = None, password: str | None = None) -> tuple[str, str]:
    """A dyndns2 request the way a Hikvision device sends it. Returns (status, body)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    auth = f"Authorization: Basic {base64.b64encode(f'{user}:{password}'.encode()).decode()}\r\n" if user else ""
    writer.write(f"GET {path} HTTP/1.0\r\nHost: members.dyndns.org\r\n{auth}User-Agent: Hikvision DDNS\r\n\r\n".encode())
    await writer.drain()
    raw = (await reader.read()).decode()
    writer.close()
    head, _, body = raw.partition("\r\n\r\n")
    return head.split("\r\n")[0].split(" ", 1)[1], body

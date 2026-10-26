"""DNS server: answers A, AAAA and SRV queries from the networks' DNS maps.

Runs on the asyncio event loop, on UDP and TCP. It tries port 53 first and
falls back to 5300 when 53 needs root or is already taken.

Names it answers:
    <host>          any hostname in the open network's map, exactly as written,
                    including ones with dots ("nas", "bing.com"); this lets a
                    network override public names for whoever uses this server
    <host>.<zone>   any network this node has joined; <zone> is the network's
                    name in lowercase with spaces etc. turned into '-'
                    (e.g. "nas.home-network")
    _<service>._<tcp|udp>.<host>[.<zone>]
                    SRV: the port a service runs on (e.g. _minecraft._tcp.mc.home).
                    A host without that service answers with no records, which
                    is what makes clients fall back to <host> and their default port.

Any other name is forwarded to an upstream DNS server (default 1.1.1.1), so
devices on the LAN can use this node as their only DNS server: set it in the
router's DHCP settings, or on the device itself. Without an upstream, other
names get REFUSED.

Which address a name gets is decided per node (see DnsModule.answer_for): a
node's hostname can be answered with its LAN IP instead of its public IP when
this node can tell it's on the same LAN.
"""

import asyncio
import ipaddress
import re
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from core.storage import Identity, RecordStore, network_folder

MAP_KEY = "dns.dns_map"  # the DNS map's key in Network.files
MAP_FIELDS = ("ip", "srv", "lan", "firewalled")

DEFAULT_PORTS = (53, 5300)
DEFAULT_UPSTREAM = "1.1.1.1"
UPSTREAM_TIMEOUT = 3
TTL = 60

TYPE_A, TYPE_AAAA, TYPE_SRV, TYPE_ANY = 1, 28, 33, 255
CLASS_IN = 1
NOERROR, FORMERR, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 3, 4, 5


def zone_of(network_name: str) -> str:
    """'Home Network' -> 'home-network'"""
    return re.sub(r"[^a-z0-9-]+", "-", network_name.lower()).strip("-") or "network"


def lan_ip() -> str:
    """This machine's address on the LAN (127.0.0.1 if it has none)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # nothing is sent; this only picks the outgoing interface
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def local_address(ip) -> bool:
    """Is this an address that only means something inside a LAN (192.168.x.x,
    10.x, fd00::, carrier-grade NAT's 100.64.x.x...)? Loopback doesn't count."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not addr.is_global and not addr.is_loopback and not addr.is_unspecified and not addr.is_multicast


@dataclass
class Srv:
    priority: int
    weight: int
    port: int
    target: str                                    # e.g. "mc.home"
    target_ips: list[str] = field(default_factory=list)


@dataclass
class Lookup:
    rcode: int
    ips: list[str] = field(default_factory=list)
    srv: list[Srv] = field(default_factory=list)


# --- where answers come from ---------------------------------------------------

class Zones:
    """Looks hostnames up in the DNS maps of every network this node has joined.
    The open network is read live; the others from disk, re-read when the file changes."""

    def __init__(self, identity: Identity, saved_networks: Path, current: Callable,
                 address: Callable[[dict, bool], str] = lambda row, live: row["ip"]):
        self.identity = identity
        self.saved = saved_networks
        self.current = current  # returns the open Network, or None
        self.address = address  # (record, from the open network?) -> the IP to answer with
        self._cache: dict[Path, tuple[float, RecordStore]] = {}

    def _map_from_disk(self, topic: str) -> RecordStore | None:
        path = network_folder(self.saved, topic) / "dns_map.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        cached = self._cache.get(path)
        if not cached or cached[0] != mtime:
            cached = (mtime, RecordStore(path, "hostname", MAP_FIELDS))
            self._cache[path] = cached
        return cached[1]

    def _find(self, name: str) -> tuple[int, dict | None, str, bool]:
        """A queried name -> (rcode, the host's record, its zone, whether it's from
        the open network). In order:
          1. the exact name in the open network's map, dots and all ('nas', 'bing.com');
             an unknown name without dots stops here (NXDOMAIN, never forwarded)
          2. '<host>.<zone>' for any network this node has joined
          3. otherwise REFUSED, which the server turns into forwarding upstream
        """
        net = self.current()
        if net and name:
            row = net.files[MAP_KEY].lookup(name)
            if row or "." not in name:
                return NOERROR, row, zone_of(net.name), True
        for entry in self.identity.networks:
            network_name = entry["network_name"]
            dns = None
            live = bool(net and net.topic == entry["topic"])
            if live:
                network_name, dns = net.name, net.files[MAP_KEY]
            zone = zone_of(network_name)
            if not name.endswith("." + zone):
                continue
            host = name[:-len(zone) - 1]
            dns = dns or self._map_from_disk(entry["topic"])
            return NOERROR, (dns.lookup(host) if dns else None), zone, live
        return REFUSED, None, "", False

    def resolve(self, qname: str) -> Lookup:
        labels = qname.rstrip(".").lower().split(".")
        prefix = []  # "_minecraft._tcp.mc.home" -> ["minecraft", "tcp"]
        while labels and labels[0].startswith("_"):
            prefix.append(labels.pop(0)[1:])

        rcode, row, zone, live = self._find(".".join(labels))
        if rcode != NOERROR:
            return Lookup(rcode)
        if not row or (prefix and len(prefix) != 2):
            return Lookup(NXDOMAIN)
        ip = self.address(row, live)
        if not prefix:
            return Lookup(NOERROR, ips=[ip])

        service, proto = prefix
        target = f"{row['hostname']}.{zone}"
        entries = row.get("srv") if isinstance(row.get("srv"), list) else []
        return Lookup(NOERROR, srv=[Srv(e["priority"], e["weight"], e["port"], target, [ip])
                                    for e in entries if e.get("service") == service and e.get("proto") == proto])


# --- DNS wire format ---------------------------------------------------------------

def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".") if label) + b"\x00"


def _address_record(name: bytes, ip: str) -> tuple[int, bytes]:
    addr = ipaddress.ip_address(ip)
    rtype = TYPE_A if addr.version == 4 else TYPE_AAAA
    return rtype, name + struct.pack("!HHIH", rtype, CLASS_IN, TTL, len(addr.packed)) + addr.packed


def answer(query: bytes, resolve: Callable[[str], Lookup]) -> bytes | None:
    """Build the response to one DNS query message. None if it can't be parsed at all."""
    if len(query) < 12:
        return None
    qid, flags, qdcount = struct.unpack("!HHH", query[:6])
    opcode = flags & 0x7800
    reply_flags = 0x8000 | opcode | 0x0400 | (flags & 0x0100)  # QR, opcode, AA, copy RD

    def reply(rcode: int, question: bytes = b"", answers: list[bytes] = (), additional: list[bytes] = ()) -> bytes:
        header = struct.pack("!HHHHHH", qid, reply_flags | rcode, 1 if question else 0,
                             len(answers), 0, len(additional))
        return header + question + b"".join(answers) + b"".join(additional)

    if opcode != 0:
        return reply(NOTIMP)
    if qdcount != 1:
        return reply(FORMERR)

    # Question: length-prefixed labels, then type and class.
    labels, pos = [], 12
    while True:
        if pos >= len(query):
            return reply(FORMERR)
        length = query[pos]
        pos += 1
        if length == 0:
            break
        if length & 0xC0 or pos + length > len(query):
            return reply(FORMERR)  # name compression isn't used in questions
        labels.append(query[pos:pos + length].decode("ascii", "replace"))
        pos += length
    if pos + 4 > len(query):
        return reply(FORMERR)
    qtype, qclass = struct.unpack("!HH", query[pos:pos + 4])
    question = query[12:pos + 4]

    found = resolve(".".join(labels))
    if found.rcode != NOERROR or qclass != CLASS_IN:
        return reply(found.rcode, question)

    question_name = b"\xc0\x0c"  # points back at the name in the question
    answers, additional = [], []
    for ip in found.ips:
        rtype, record = _address_record(question_name, ip)
        if qtype in (rtype, TYPE_ANY):
            answers.append(record)
    if qtype in (TYPE_SRV, TYPE_ANY):
        for srv in found.srv:
            rdata = struct.pack("!HHH", srv.priority, srv.weight, srv.port) + encode_name(srv.target)
            answers.append(question_name + struct.pack("!HHIH", TYPE_SRV, CLASS_IN, TTL, len(rdata)) + rdata)
            # The target's address too, so the client needs no second lookup.
            additional += [_address_record(encode_name(srv.target), ip)[1] for ip in srv.target_ips]
    return reply(NOERROR, question, answers, additional)


# --- the server ----------------------------------------------------------------------

def _is_refused(response: bytes) -> bool:
    return len(response) >= 4 and (response[3] & 0x0F) == REFUSED


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: "DNSServer"):
        self.server = server
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self._reply(data, addr))

    async def _reply(self, data, addr):
        response = await self.server.handle(data)
        if response and not self.transport.is_closing():
            self.transport.sendto(response, addr)

    def error_received(self, exc):
        pass  # e.g. the client went away before the answer arrived


class _UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future):
        self.future = future

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)


class DNSServer:
    def __init__(self, resolve: Callable[[str], tuple[int, list[str]]], upstream: str | None = DEFAULT_UPSTREAM):
        self.resolve = resolve
        self.upstream = upstream  # None: don't forward, answer REFUSED
        self.port: int | None = None
        self._udp = None
        self._tcp = None

    async def handle(self, query: bytes, tcp: bool = False) -> bytes | None:
        """Answer from our zones; forward anything else upstream."""
        response = answer(query, self.resolve)
        if response and self.upstream and _is_refused(response):
            forwarded = await (self._forward_tcp(query) if tcp else self._forward_udp(query))
            if forwarded:
                return forwarded
            # Upstream didn't answer: tell the client it failed (SERVFAIL), not that it's refused.
            return response[:3] + bytes([(response[3] & 0xF0) | 2]) + response[4:]
        return response

    async def _forward_udp(self, query: bytes) -> bytes | None:
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        try:
            transport, _ = await loop.create_datagram_endpoint(lambda: _UpstreamProtocol(future),
                                                               remote_addr=(self.upstream, 53))
        except OSError:
            return None
        try:
            transport.sendto(query)
            return await asyncio.wait_for(future, UPSTREAM_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            return None
        finally:
            transport.close()

    async def _forward_tcp(self, query: bytes) -> bytes | None:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(self.upstream, 53), UPSTREAM_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            return None
        try:
            writer.write(struct.pack("!H", len(query)) + query)
            await writer.drain()
            size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), UPSTREAM_TIMEOUT))[0]
            return await asyncio.wait_for(reader.readexactly(size), UPSTREAM_TIMEOUT)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
            return None
        finally:
            writer.close()

    async def start(self, host: str = "0.0.0.0", ports: tuple[int, ...] = DEFAULT_PORTS) -> int:
        """Listen on the first port that works. Returns it."""
        loop = asyncio.get_running_loop()
        problems = []
        for port in ports:
            udp = None
            try:
                udp, _ = await loop.create_datagram_endpoint(lambda: _UdpProtocol(self), local_addr=(host, port))
                self._tcp = await asyncio.start_server(self._handle_tcp, host, port)
            except OSError as e:
                # PermissionError: ports below 1024 need root (Linux/macOS).
                # Address in use: another DNS server, e.g. systemd-resolved, has it.
                if udp:
                    udp.close()
                reason = "needs root/administrator" if isinstance(e, PermissionError) else (e.strerror or str(e))
                problems.append(f"port {port}: {reason}")
                continue
            self._udp, self.port = udp, port
            return port
        raise RuntimeError("DNS server couldn't start (" + "; ".join(problems) + ")")

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # Over TCP every message is prefixed with its length (2 bytes).
        try:
            while True:
                size = struct.unpack("!H", await reader.readexactly(2))[0]
                response = await self.handle(await reader.readexactly(size), tcp=True)
                if not response:
                    break
                writer.write(struct.pack("!H", len(response)) + response)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    def close(self):
        if self._udp:
            self._udp.close()
        if self._tcp:
            self._tcp.close()

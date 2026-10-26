"""DDNS update endpoint: lets devices on the LAN (Hikvision cameras/NVRs,
routers, ...) send their IP to this node, which signs it and pushes it to the
decentralized network.

Speaks the dyndns2 protocol, which is what Hikvision's "DynDNS" and "NO-IP"
DDNS types, and most routers, use:

    GET /nic/update?hostname=cam1.home&myip=192.168.1.64
    Authorization: Basic <username:password>

    -> "good 192.168.1.64"   updated
       "nochg 192.168.1.64"  already had that IP
       "badauth"             wrong username or password
       "notfqdn"             no hostname given
       "nohost"              this login may not update that hostname, or this
                             node may not (needs admin rights or /dns -delegate)
       "dnserr"              the IP isn't valid
       "911"                 this node isn't on a network right now

If the device doesn't send myip, the address the request came from is used.
Several hostnames can be sent comma-separated; there's one answer line each.

Listens on port 80 first (some devices can't be told to use another port),
then 8080 if 80 needs root or is taken. Runs on the asyncio loop.
"""

import asyncio
import base64
import binascii
import ipaddress
import urllib.parse
from typing import Callable

from modules.ddns.users import DdnsUsers
from modules.dns.server import zone_of

DEFAULT_PORTS = (80, 8080)
UPDATE_PATHS = ("/nic/update", "/update", "/")
MAX_REQUEST = 8192


class DDNSEndpoint:
    def __init__(self, users: DdnsUsers, dns, log: Callable[[str], None]):
        self.users = users
        self.dns = dns  # the DNS module: its .net is the open network (or None)
        self.log = log
        self.port: int | None = None
        self._server = None

    async def start(self, host: str = "0.0.0.0", ports: tuple[int, ...] = DEFAULT_PORTS) -> int:
        """Listen on the first port that works. Returns it."""
        problems = []
        for port in ports:
            try:
                self._server = await asyncio.start_server(self._handle, host, port)
            except OSError as e:
                reason = "needs root/administrator" if isinstance(e, PermissionError) else (e.strerror or str(e))
                problems.append(f"port {port}: {reason}")
                continue
            self.port = port
            return port
        raise RuntimeError("DDNS endpoint couldn't start (" + "; ".join(problems) + ")")

    def close(self):
        if self._server:
            self._server.close()

    # --- HTTP -------------------------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
            writer.close()
            return
        try:
            status, body, extra = await self._respond(head[:MAX_REQUEST], writer.get_extra_info("peername"))
        except Exception as e:  # never let one bad request take the endpoint down
            self.log(f"! DDNS request failed: {e}")
            status, body, extra = "500 Internal Server Error", "911", {}
        headers = {"Content-Type": "text/plain; charset=utf-8", "Content-Length": str(len(body.encode())),
                   "Connection": "close", **extra}
        writer.write((f"HTTP/1.1 {status}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                      + "\r\n" + body).encode())
        try:
            await writer.drain()
        except ConnectionError:
            pass
        writer.close()

    async def _respond(self, head: bytes, peer) -> tuple[str, str, dict]:
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split()
        if len(parts) != 3 or parts[0] not in ("GET", "POST"):
            return "400 Bad Request", "badrequest", {}
        url = urllib.parse.urlsplit(parts[1])
        if url.path.rstrip("/") not in {p.rstrip("/") for p in UPDATE_PATHS}:
            return "404 Not Found", "notfound", {}
        params = {k: v[-1] for k, v in urllib.parse.parse_qs(url.query).items()}
        headers = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:] if ":" in l)}

        username, password = self._credentials(headers, params)
        if username is None:
            # Ask for a login; most clients only send it after this challenge.
            return "401 Unauthorized", "badauth", {"WWW-Authenticate": 'Basic realm="DDNS"'}

        client_ip = peer[0] if peer else ""
        answers = await self.update(username, password, params.get("hostname", ""), params.get("myip", ""), client_ip)
        return "200 OK", "\n".join(answers), {}

    @staticmethod
    def _credentials(headers: dict, params: dict) -> tuple[str | None, str]:
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                user, _, pw = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace").partition(":")
                return user, pw
            except (binascii.Error, ValueError):
                return None, ""
        if "username" in params:  # a few clients put the login in the URL instead
            return params["username"], params.get("password", "")
        return None, ""

    # --- the update -------------------------------------------------------------

    async def update(self, username: str, password: str, hostnames: str, myip: str, client_ip: str) -> list[str]:
        login = self.users.check(username, password)
        if not login:
            self.log(f"! DDNS: wrong login for '{username}' from {client_ip}")
            return ["badauth"]
        hosts = [h.strip().lower() for h in hostnames.split(",") if h.strip()]
        if not hosts:
            return ["notfqdn"]

        try:
            addr = ipaddress.ip_address((myip or client_ip).strip())
            if addr.version == 6 and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            ip = str(addr)
        except ValueError:
            return ["dnserr"] * len(hosts)

        net = self.dns.net
        if not net:
            self.log(f"! DDNS: '{username}' sent an update, but this node isn't on a network")
            return ["911"] * len(hosts)

        answers = []
        for fqdn in hosts:
            host = self._bare(fqdn, net)
            if not host or host not in login["hostnames"]:
                self.log(f"! DDNS: '{username}' may not update {fqdn}")
                answers.append("nohost")
            elif not self.dns.may_update(host):
                self.log(f"! DDNS: this node may not update {host} (needs admin rights or /dns -delegate)")
                answers.append("nohost")
            elif (row := self.dns.dns_map.lookup(host)) and row["ip"] == ip:
                answers.append(f"nochg {ip}")
            else:
                await self.dns.set_dns(host, ip)
                self.log(f"* DDNS: {username} updated {host} -> {ip}")
                answers.append(f"good {ip}")
        return answers

    @staticmethod
    def _bare(fqdn: str, net) -> str | None:
        """'cam1' or 'cam1.<zone of the open network>' -> 'cam1'; anything else -> None."""
        if "." not in fqdn:
            return fqdn
        host, _, zone = fqdn.partition(".")
        return host if zone == zone_of(net.name) else None

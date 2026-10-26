"""DNS module: the network's DNS map, who may change it, node hostnames, and a
DNS server for the LAN.

Files (in the network's folder, synced record by record):
    dns_map.json           hostname -> IP. A record may be signed by an admin,
                           by a key the hostname is delegated to, or (for its
                           automatic n-<key> hostname) by the node itself.
    dns_delegations.json   who besides admins may update a hostname; "node"
                           marks a hostname that follows that node's own IP.

Every node gets the hostname n-<first 12 chars of its key> automatically, and
admins can assign friendly names (/dns -assign). A node keeps all of its
hostnames pointed at its public IP by itself, and re-signs them weekly even
when its IP stays the same. A hostname that follows a node expires after
NODE_RECORD_DAYS without that: the node is gone, so every node drops it.
Hostnames set by hand (/dns -append) never expire.

Which address a node's hostname is answered with depends on who answers
(see answer_for). With its public IP a node also publishes, signed, its LAN
IP ("lan") and whether inbound connections are blocked ("firewalled": behind
NAT or a firewall without forwarded ports; carrier-grade NAT always is). The
DNS server then answers:
    this node's own hostnames       with its current LAN IP
    a node on the same LAN          with that node's LAN IP, if our own
                                    Hyperswarm connection to it comes from
                                    exactly that address
    anything else                   with the public IP
"firewalled" doesn't change the answer: a port forwarded to a service can
still work while the DHT's own port is blocked. It's shown, so people know
when a public IP won't work for them.

A record can also list services with their ports ("srv"), served as SRV
records such as _minecraft._tcp.mc.home -> port 25565. They're optional: a
record without them is exactly what it was before, and SRV queries for it get
no answer, so clients fall back to the hostname and their default port.
Whoever may update a hostname may set its services; IP updates keep them.
"""

import ipaddress
import json
import re

from core.module import CommandError, Module, RecordFile, command
from core.network import KEY
from core.storage import days_ago, parse_time
from modules.dns.server import (DEFAULT_PORTS, DEFAULT_UPSTREAM, MAP_FIELDS, DNSServer, Zones, lan_ip,
                                local_address, zone_of)

HOSTNAME = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
SERVICE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
PROTOCOLS = ("tcp", "udp")
MAX_SERVICES = 16  # per hostname
NODE_RECORD_DAYS = 90  # a hostname following a node expires when it hasn't been re-signed for this long
REFRESH_DAYS = 7       # a node re-signs its hostnames when they're this old, even if its IP is the same


def clean_srv(entries) -> list[dict]:
    """A record's services in canonical form (what's signed), sorted by service."""
    out = []
    for e in entries if isinstance(entries, list) else []:
        if isinstance(e, dict):
            out.append({"service": str(e.get("service") or "").lower(), "proto": str(e.get("proto") or "").lower(),
                        "port": int(e.get("port") or 0), "priority": int(e.get("priority") or 0),
                        "weight": int(e.get("weight") or 0)})
    return sorted(out, key=lambda e: (e["service"], e["proto"]))


def srv_problem(entries: list[dict]) -> str | None:
    if len(entries) > MAX_SERVICES:
        return f"more than {MAX_SERVICES} services"
    seen = set()
    for e in entries:
        name = f"_{e['service']}._{e['proto']}"
        if not SERVICE.fullmatch(e["service"]):
            return f"invalid service name '{e['service']}'"
        if e["proto"] not in PROTOCOLS:
            return f"protocol must be tcp or udp, not '{e['proto']}'"
        if not 1 <= e["port"] <= 65535:
            return f"invalid port {e['port']} for {name}"
        if not (0 <= e["priority"] <= 65535 and 0 <= e["weight"] <= 65535):
            return f"priority and weight must be 0-65535 for {name}"
        if name in seen:
            return f"{name} is listed twice"
        seen.add(name)
    return None


def node_hostname(key: str) -> str:
    """The hostname every node gets automatically, e.g. 'n-1d7afd64eb69'. Only
    that node (and admins) may update it, so nobody else can claim it."""
    return f"n-{key[:12]}"


class DnsModule(Module):
    name = "dns"
    title = "DNS"
    # Delegations first, so a newly delegated key's records are accepted in the same sync.
    files = [RecordFile("dns_delegations", key="hostname", fields=("delegates", "node"), lowercase_key=True),
             RecordFile("dns_map", key="hostname", fields=MAP_FIELDS, lowercase_key=True)]

    def __init__(self, controller):
        super().__init__(controller)
        self.server: DNSServer | None = None

    # --- data -----------------------------------------------------------------

    @property
    def dns_map(self):
        return self.store("dns_map")

    @property
    def delegations(self):
        return self.store("dns_delegations")

    def delegates_of(self, hostname: str) -> list[str]:
        row = self.delegations.lookup(hostname.lower())
        delegates = row.get("delegates") if row else None
        return [d for d in delegates if isinstance(d, str)] if isinstance(delegates, list) else []

    def node_of(self, hostname: str) -> str:
        row = self.delegations.lookup(hostname.lower())
        return str(row.get("node") or "") if row else ""

    def may_update(self, hostname: str, key: str | None = None) -> bool:
        """Admins may update any hostname; other keys only hostnames delegated
        to them, and their own automatic n-<key> hostname."""
        key = key or self.net.me
        hostname = hostname.lower()
        return self.net.is_admin(key) or hostname == node_hostname(key) or key in self.delegates_of(hostname)

    def hostnames_of(self, key: str) -> list[str]:
        """Hostnames that follow this node's IP: its automatic one, plus any an
        admin assigned to it with /dns -assign."""
        assigned = [r["hostname"] for r in self.delegations.active()
                    if r.get("node") == key and key in self.delegates_of(r["hostname"])]
        return [node_hostname(key)] + sorted(assigned)

    def fqdns(self, key: str) -> list[str]:
        zone = zone_of(self.net.name)
        return [f"{h}.{zone}" for h in self.hostnames_of(key)]

    # --- records: canonical form and who may write them -----------------------

    def clean_record(self, file_name: str, row: dict) -> dict:
        if file_name == "dns_map":
            # Optional fields are only present when set, so records without them
            # are signed exactly as before they existed.
            rec = {"ip": str(row.get("ip") or "")}
            srv = clean_srv(row.get("srv"))
            if srv:
                rec["srv"] = srv
            if row.get("lan"):
                rec["lan"] = str(row["lan"])
            if row.get("firewalled") is True:
                rec["firewalled"] = True
            return rec
        delegates = row.get("delegates")
        rec = {"delegates": sorted({d for d in delegates if isinstance(d, str)}) if isinstance(delegates, list) else []}
        if row.get("node"):  # only present when set
            rec["node"] = str(row["node"])
        return rec

    def validate_record(self, file_name: str, rec: dict, signer: str) -> str | None:
        host = rec["hostname"]
        if not HOSTNAME.fullmatch(host):
            return "invalid hostname"
        if file_name == "dns_delegations":
            if not self.net.is_admin(signer):
                return f"{self.net.name_of(signer)} isn't an admin"
            if not all(KEY.fullmatch(d) for d in rec.get("delegates", [])):
                return "invalid delegate key"
            return None
        if not self.may_update(host, signer):
            return f"{self.net.name_of(signer)} may not update {host}"
        if not rec.get("deleted"):
            try:
                ipaddress.ip_address(rec["ip"])
            except ValueError:
                return f"invalid IP address for {host}"
            problem = srv_problem(rec.get("srv", []))
            if problem:
                return f"{host}: {problem}"
            if "lan" in rec and not local_address(rec["lan"]):
                return f"{host}: its LAN address {rec['lan']} isn't a LAN address"
        return None

    def follows_node(self, hostname: str) -> bool:
        return hostname.startswith("n-") or bool(self.node_of(hostname))

    def expires(self, file_name: str, rec: dict) -> float | None:
        if file_name == "dns_map" and self.follows_node(rec["hostname"]):
            return NODE_RECORD_DAYS
        return None

    def describe_record(self, file_name: str, rec: dict) -> str:
        host = rec["hostname"]
        if file_name == "dns_delegations":
            if rec.get("node"):
                whose = "your" if rec["node"] == self.net.me else f"{self.net.name_of(rec['node'])}'s"
                return f"{host} now follows {whose} IP"
            who = ", ".join(self.net.name_of(k) for k in rec.get("delegates", [])) or "only admins"
            return f"{host} may now be updated by: {who}"
        if rec.get("deleted"):
            return f"DNS {host} removed"
        services = ", ".join(f"_{s['service']}._{s['proto']}:{s['port']}" for s in rec.get("srv", []))
        return f"DNS {host} -> {rec['ip']}" + (f"  (services: {services})" if services else "")

    # --- changes ----------------------------------------------------------------

    async def set_dns(self, hostname: str, ip: str, **reach) -> dict:
        """Set a hostname's IP. Its services (SRV), LAN IP and firewalled flag stay
        as they were, unless given in `reach` (lan=..., firewalled=...)."""
        current = self.dns_map.lookup(hostname.lower()) or {}
        keep = {"srv": current.get("srv"), "lan": current.get("lan"), "firewalled": current.get("firewalled")}
        return await self.write_record("dns_map", hostname, ip=ip, **(keep | reach))

    async def set_services(self, hostname: str, entries: list[dict]) -> dict:
        """Replace a hostname's services. The hostname must already have an IP."""
        current = self.dns_map.lookup(hostname.lower())
        if not current:
            raise CommandError(f"{hostname} isn't in the DNS map yet; an SRV record points at its IP, so set that first")
        return await self.write_record("dns_map", hostname, ip=current["ip"], srv=entries,
                                       lan=current.get("lan"), firewalled=current.get("firewalled"))

    def services_of(self, hostname: str) -> list[dict]:
        return clean_srv((self.dns_map.lookup(hostname.lower()) or {}).get("srv"))

    async def remove_dns(self, hostname: str) -> dict:
        if not self.net.is_admin():
            raise PermissionError("only admins can remove DNS entries")
        if not self.dns_map.lookup(hostname.lower()):
            raise CommandError(f"{hostname} isn't in the DNS map")
        return await self.write_record("dns_map", hostname, deleted=True)

    async def delegate(self, hostname: str, key: str, allow: bool) -> dict:
        """Let `key` update `hostname` (allow=True), or take that right away."""
        delegates = set(self.delegates_of(hostname))
        if allow == (key in delegates):
            raise CommandError(f"{self.net.name_of(key)} {'already may' if allow else 'may not'} update {hostname}")
        delegates = delegates | {key} if allow else delegates - {key}
        node = self.node_of(hostname)
        if node and node not in delegates:
            node = ""  # the node it followed lost its right to it
        return await self.write_record("dns_delegations", hostname, delegates=sorted(delegates), node=node)

    async def assign(self, hostname: str, key: str) -> dict:
        """Give `key` a hostname that follows its own IP: its node keeps the
        record up to date by itself. Replaces whoever it was assigned to before."""
        hostname = hostname.lower()
        if hostname.startswith("n-"):
            raise CommandError("hostnames starting with 'n-' are reserved for the automatic node names")
        previous = self.node_of(hostname)
        if previous == key:
            raise CommandError(f"{hostname} is already assigned to {self.net.name_of(key)}")
        delegates = (set(self.delegates_of(hostname)) - {previous}) | {key}
        rec = await self.write_record("dns_delegations", hostname, delegates=sorted(delegates), node=key)
        if key == self.net.me:
            await self.publish_own_ip()
        return rec

    # --- which address to answer with ----------------------------------------------

    def own_reachability(self) -> dict:
        """What this node publishes next to its public IP: its LAN IP (None if it
        has none) and whether inbound connections to it are blocked."""
        lan = lan_ip()
        return {"lan": lan if local_address(lan) else None, "firewalled": bool(self.controller.api.firewalled)}

    def node_behind(self, row: dict, live: bool) -> str:
        """The key of the node a hostname follows, or "" for a hostname set by hand.
        live: the record is from the open network (whose delegations we have)."""
        host, signer = row["hostname"], str(row.get("updated_by") or "")
        if live and self.net:
            node = self.node_of(host)
            if node:
                return node
        return signer if signer and host == node_hostname(signer) else ""

    def answer_for(self, row: dict, live: bool = True) -> str:
        """The address this node's DNS server answers with for a record."""
        address, _ = self.explain_answer(row, live)
        return address

    def explain_answer(self, row: dict, live: bool = True) -> tuple[str, str]:
        """(address to answer with, why it isn't the public IP or "")."""
        node = self.node_behind(row, live)
        if node and node == self.controller.api.public_key:
            mine = lan_ip()
            if local_address(mine):
                return mine, "this node, so its LAN IP"
        lan = str(row.get("lan") or "")
        if live and node and lan and self.net and self.net.addresses.get(node) == lan:
            return lan, "same LAN as this node"
        return row["ip"], ""

    async def publish_own_ip(self):
        """Point this node's own hostnames at its current public IP, signed with
        its own key. Unchanged ones are re-signed once they're REFRESH_DAYS old,
        so they don't expire while this node is still around."""
        ip = self.controller.api.public_ip
        if not ip or not self.net:
            return
        reach = self.own_reachability()
        changed = []
        for host in self.hostnames_of(self.net.me):
            row = self.dns_map.lookup(host)
            if not self.may_update(host):
                continue
            if row and row["ip"] == ip:
                same = (row.get("lan") or None) == reach["lan"] and bool(row.get("firewalled")) == reach["firewalled"]
                signed = parse_time(row.get("last_modified"))
                if same and signed and signed > days_ago(REFRESH_DAYS):
                    continue
                await self.set_dns(host, ip, **reach)  # same public IP: nothing to tell the user
                continue
            await self.set_dns(host, ip, **reach)
            changed.append(host)
        if changed:
            self.notify(f"* your hostname{'s' if len(changed) > 1 else ''} {', '.join(changed)} -> {ip}")

    # --- hooks --------------------------------------------------------------------

    async def start(self):
        if self.options.get("no_dns"):
            return None
        host = self.options.get("host", "0.0.0.0")
        upstream = self.options.get("upstream", DEFAULT_UPSTREAM)
        upstream = None if str(upstream).lower() == "none" else upstream
        zones = Zones(self.controller.identity, self.controller.saved, lambda: self.net, self.answer_for)
        self.server = DNSServer(zones.resolve, upstream)
        try:
            port = await self.server.start(host, tuple(self.options.get("dns_ports") or DEFAULT_PORTS))
        except RuntimeError as e:
            self.server = None
            return f"! {e}. Continuing without the DNS server."
        note = "" if port == 53 else "  (port 53 wasn't available)"
        forward = f", forwarding other names to {upstream}" if upstream else ""
        return f"DNS server listening on {host}:{port}{forward}{note}"

    async def stop(self):
        if self.server:
            self.server.close()

    async def on_public_ip(self, ip: str):
        await self.publish_own_ip()

    async def maintain(self):
        await self.publish_own_ip()

    async def on_records(self, file_name: str, records: list[dict], from_peer: str):
        if file_name == "dns_delegations" and any(r.get("node") == self.net.me for r in records):
            await self.publish_own_ip()  # an admin assigned us a hostname

    def network_info(self) -> list[str]:
        if self.server and self.server.port:
            return [f"  DNS:      <host>.{zone_of(self.net.name)} (or just <host>) on port {self.server.port}"]
        return ["  DNS:      server not running"]

    def user_info(self, key: str) -> list[str]:
        reach = self.own_reachability()
        inbound = ("blocked (behind NAT or a firewall): from outside your LAN, only ports forwarded to "
                   "this machine work" if reach["firewalled"] else "open")
        return [f"  hostnames: {', '.join(self.fqdns(key))}",
                f"  LAN IP:    {reach['lan'] or '(none)'}",
                f"  inbound:   {inbound}"]

    def peer_tags(self, key: str) -> str:
        return ", ".join(self.fqdns(key))

    # --- commands -----------------------------------------------------------------

    @command("dns", "list", help="shows the DNS map and who may update each entry")
    def cmd_list(self, arg):
        n = self.net
        rows = self.dns_map.active()
        out = [] if rows else ["  (no entries)"]
        for r in rows:
            host = r["hostname"]
            by = r.get("updated_by") or ""
            node = self.node_of(host) or (by if host == node_hostname(by) else "")
            delegates = ", ".join(n.name_of(k) for k in self.delegates_of(host))
            note = (f"   follows {n.name_of(node)}'s IP" if node
                    else f"   delegated to: {delegates}" if delegates else "")
            out.append(f"  {host:24} {r['ip']:16} by {n.name_of(by):12} {r.get('last_modified') or '-'}{note}")
            reach = [f"LAN {r['lan']}"] if r.get("lan") else []
            if r.get("firewalled"):
                reach.append("behind NAT/firewall: its public IP only works for forwarded ports")
            address, why = self.explain_answer(r)
            if why:
                reach.append(f"answered here with {address} ({why})")
            if reach:
                out.append(f"    {'; '.join(reach)}")
            for s in clean_srv(r.get("srv")):
                extra = f"  (priority {s['priority']}, weight {s['weight']})" if s["priority"] or s["weight"] else ""
                out.append(f"    SRV _{s['service']}._{s['proto']}.{host} -> port {s['port']}{extra}")
        for r in self.delegations.active():  # delegated but not set yet
            if r.get("delegates") and not self.dns_map.lookup(r["hostname"]):
                names = ", ".join(n.name_of(k) for k in self.delegates_of(r["hostname"]))
                out.append(f"  {r['hostname']:24} {'(not set yet)':16} delegated to: {names}")
        return out

    @command("dns", "append", '{"<HOST>": "<IP>"}', help="adds or updates entries (admins, or delegated users)")
    async def cmd_append(self, arg):
        entries = self.dns_payload(arg)
        denied = [h for h in entries if not self.may_update(h)]  # check all before changing anything
        if denied:
            raise PermissionError(f"you may not update {', '.join(denied)}. Only admins, and users a "
                                  f"hostname is delegated to, can.")
        out = []
        for host, ip in entries.items():
            await self.set_dns(host, ip)
            out.append(f"  DNS {host} -> {ip}")
        return out

    @command("dns", "remove", "<HOST>", admin=True, help="removes a DNS entry")
    async def cmd_remove(self, arg):
        out = []
        for host in (h.lower() for h in self.controller.list_payload(arg)):
            if not self.dns_map.lookup(host):
                out.append(f"  ! {host} isn't in the DNS map, skipped")
                continue
            await self.remove_dns(host)
            out.append(f"  DNS {host} removed")
        return out

    @command("dns", "srv", "<HOST> <SERVICE> <tcp|udp> <PORT> [PRIORITY WEIGHT]",
             help="adds or changes a service port on a hostname (SRV)")
    async def cmd_srv(self, arg):
        parts = arg.split()
        if len(parts) not in (4, 6):
            raise CommandError("usage: /dns -srv <HOST> <SERVICE> <tcp|udp> <PORT> [PRIORITY WEIGHT]"
                               "   e.g. /dns -srv mc minecraft tcp 25565")
        host, service, proto = parts[0].lower(), parts[1].lstrip("_").lower(), parts[2].lstrip("_").lower()
        try:
            port, priority, weight = int(parts[3]), *(int(p) for p in parts[4:6] or (0, 0))
        except ValueError:
            raise CommandError("port, priority and weight must be numbers")
        if not self.may_update(host):
            raise PermissionError(f"you may not update {host}. Only admins, and users it's delegated to, can.")
        entry = {"service": service, "proto": proto, "port": port, "priority": priority, "weight": weight}
        entries = [e for e in self.services_of(host) if (e["service"], e["proto"]) != (service, proto)] + [entry]
        problem = srv_problem(clean_srv(entries))
        if problem:
            raise CommandError(problem)
        await self.set_services(host, entries)
        zone = zone_of(self.net.name)
        return f"  SRV _{service}._{proto}.{host}.{zone} -> {host}.{zone} port {port}"

    @command("dns", "unsrv", "<HOST> <SERVICE> <tcp|udp>", help="removes a service port from a hostname")
    async def cmd_unsrv(self, arg):
        parts = arg.split()
        if len(parts) != 3:
            raise CommandError("usage: /dns -unsrv <HOST> <SERVICE> <tcp|udp>")
        host, service, proto = parts[0].lower(), parts[1].lstrip("_").lower(), parts[2].lstrip("_").lower()
        if not self.may_update(host):
            raise PermissionError(f"you may not update {host}. Only admins, and users it's delegated to, can.")
        entries = self.services_of(host)
        kept = [e for e in entries if (e["service"], e["proto"]) != (service, proto)]
        if len(kept) == len(entries):
            raise CommandError(f"{host} has no _{service}._{proto} service")
        await self.set_services(host, kept)
        return f"  removed _{service}._{proto} from {host}"

    def _host_and_user(self, arg: str, usage: str) -> tuple[str, str]:
        parts = arg.split()
        if len(parts) != 2:
            raise CommandError(f"usage: {usage}")
        if not HOSTNAME.fullmatch(parts[0]):
            raise CommandError(f"invalid hostname '{parts[0]}'")
        return parts[0].lower(), self.controller.resolve(parts[1])

    @command("dns", "assign", "<HOST> <ID>", admin=True, help="gives a user a hostname that follows their IP")
    async def cmd_assign(self, arg):
        host, key = self._host_and_user(arg, "/dns -assign <HOST> <ID>")
        await self.assign(host, key)
        return f"  {host} now follows {self.net.name_of(key)}'s IP; their node keeps it up to date"

    @command("dns", "delegate", "<HOST> <ID>", admin=True, help="lets a user update that hostname")
    async def cmd_delegate(self, arg):
        host, key = self._host_and_user(arg, "/dns -delegate <HOST> <ID>")
        await self.delegate(host, key, allow=True)
        return f"  {self.net.name_of(key)} may now update {host}"

    @command("dns", "undelegate", "<HOST> <ID>", admin=True, help="takes that right away again")
    async def cmd_undelegate(self, arg):
        host, key = self._host_and_user(arg, "/dns -undelegate <HOST> <ID>")
        await self.delegate(host, key, allow=False)
        return f"  {self.net.name_of(key)} may no longer update {host}"

    @staticmethod
    def dns_payload(payload: str) -> dict[str, str]:
        if payload.startswith("{"):
            try:
                entries = json.loads(payload)
            except json.JSONDecodeError as e:
                raise CommandError(f'invalid JSON: {e}. Example: /dns -append {{"nas": "192.168.1.20"}}')
            if not isinstance(entries, dict):
                raise CommandError('expected {"<HOST>": "<IP>"}')
        else:
            parts = payload.split()
            if len(parts) != 2:
                raise CommandError('usage: /dns -append {"<HOST>": "<IP>"}   or   /dns -append <HOST> <IP>')
            entries = {parts[0]: parts[1]}
        for host, ip in entries.items():
            if not HOSTNAME.fullmatch(str(host)):
                raise CommandError(f"invalid hostname '{host}'")
            try:
                ipaddress.ip_address(str(ip))
            except ValueError:
                raise CommandError(f"invalid IP address '{ip}' for {host}")
        return {str(h).lower(): str(i) for h, i in entries.items()}


MODULE = DnsModule

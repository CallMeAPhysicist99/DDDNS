"""DDNS module: lets devices on the LAN (Hikvision cameras/NVRs, routers) send
their IP to this node over dyndns2; the node signs it and pushes it to the
network through the DNS module. Needs the dns module.
"""

from core.module import CommandError, Module, command
from modules.ddns.endpoint import DEFAULT_PORTS, DDNSEndpoint
from modules.ddns.users import DdnsUsers
from modules.dns import HOSTNAME
from modules.dns.server import lan_ip, zone_of


class DdnsModule(Module):
    name = "ddns"
    title = "DDNS updates from devices on your LAN"
    requires = ("dns",)

    def __init__(self, controller):
        super().__init__(controller)
        self.users = DdnsUsers(controller.saved.parent / "ddns_users.json")
        self.endpoint: DDNSEndpoint | None = None

    @property
    def dns(self):
        return self.controller.modules["dns"]

    async def start(self):
        if self.options.get("no_ddns"):
            return None
        host = self.options.get("host", "0.0.0.0")
        self.endpoint = DDNSEndpoint(self.users, self.dns, self.notify)
        try:
            port = await self.endpoint.start(host, tuple(self.options.get("ddns_ports") or DEFAULT_PORTS))
        except RuntimeError as e:
            self.endpoint = None
            return f"! {e}. Continuing without DDNS updates."
        note = "" if port == 80 else "  (port 80 wasn't available)"
        return f"DDNS endpoint listening on {host}:{port} (dyndns2, /nic/update){note}"

    async def stop(self):
        if self.endpoint:
            self.endpoint.close()

    @command("ddns", "list", needs_network=False, help="shows DDNS logins and how to set up a device")
    def cmd_list(self, arg):
        users = self.users.all()
        out = [] if users else ["  (no DDNS logins yet; add one with /ddns -adduser)"]
        out += [f"  {u['username']:16} may update: {', '.join(u['hostnames'])}" for u in users]
        if self.endpoint and self.endpoint.port:
            port = self.endpoint.port
            domain = f"<host>.{zone_of(self.net.name)}" if self.net else "<host>.<zone>"
            out += ["", "  Device setup (e.g. Hikvision: Network > DDNS, type DynDNS):",
                    f"    server address:  {lan_ip()}" + ("" if port == 80 else f":{port}"),
                    f"    domain:          {domain}",
                    "    user / password: a login from the list above"]
            if port != 80:
                out.append("  ! port 80 wasn't available, and some devices can't be given a port.")
        else:
            out.append("  ! the DDNS endpoint isn't running")
        if self.net:
            for u in users:
                blocked = [h for h in u["hostnames"] if not self.dns.may_update(h)]
                if blocked:
                    out.append(f"  ! this node may not update {', '.join(blocked)} on '{self.net.name}' "
                               f"(needs admin rights or /dns -delegate)")
        return out

    @command("ddns", "adduser", "<USER> <HOST>[,<HOST>]", needs_network=False,
             help="lets a device (camera, router) update those hostnames")
    async def cmd_adduser(self, arg):
        parts = arg.split(maxsplit=1)
        if len(parts) != 2:
            raise CommandError("usage: /ddns -adduser <USER> <HOST>[,<HOST>...]")
        username = parts[0]
        hosts = [h.strip().lower() for h in parts[1].replace(" ", ",").split(",") if h.strip()]
        bad = [h for h in hosts if "." in h or not HOSTNAME.fullmatch(h)]
        if bad:
            raise CommandError(f"use bare hostnames like 'cam1', not {', '.join(bad)}")
        password = await self.ask(f"Password for '{username}': ", secret=True)
        self.users.add(username, password, hosts)
        out = [f"  '{username}' may now update {', '.join(hosts)} through this node"]
        if self.net:
            blocked = [h for h in hosts if not self.dns.may_update(h)]
            if blocked:
                out.append(f"  ! but this node may not update {', '.join(blocked)} on '{self.net.name}' yet: an "
                           f"admin must run " + " and ".join(f"/dns -delegate {h} {self.net.alias}" for h in blocked))
        return out

    @command("ddns", "removeuser", "<USER>", needs_network=False, help="deletes a DDNS login")
    def cmd_removeuser(self, arg):
        if not self.users.remove(arg.strip()):
            raise CommandError(f"no DDNS login '{arg.strip()}'")
        return f"  '{arg.strip()}' removed"


MODULE = DdnsModule

"""DNS module: the DNS server (port fallback, answers, forwarding), node
hostnames (automatic n- names, assigned names that follow a node's IP) and
which address each node answers with (LAN IP or public IP).

The test nodes all run on this PC, so they're on the same LAN: node hostnames
are answered with the LAN IP unless a test says otherwise."""

import asyncio

from modules.dns import node_hostname
from modules.dns.server import REFUSED, DNSServer, Lookup, lan_ip
from tests.harness import dns_entries, fresh_dir, network_of, tcp_ask, udp_ask, wait

LAN = lan_ip()


async def run(t):
    base = fresh_dir("dns")
    admin, bob = await network_of(base, "admin", "bob", no_dns=False, dns_ports=[5311, 5312])
    dns_a, dns_b = admin.module("dns"), bob.module("dns")
    t.check("the first DNS server gets its first-choice port", dns_a.server.port == 5311, str(admin.startup))
    t.check("a second server falls back when that port is taken", dns_b.server.port == 5312, str(bob.startup))
    port = dns_a.server.port

    await admin.run('/dns -append {"nas": "192.168.1.20", "v6host": "fd00::7"}')
    t.check("A record over UDP", await udp_ask(port, "nas.home") == ("NOERROR", ["192.168.1.20"]))
    t.check("bare name for the open network", await udp_ask(port, "nas") == ("NOERROR", ["192.168.1.20"]))
    t.check("names are case-insensitive", await udp_ask(port, "NAS.Home") == ("NOERROR", ["192.168.1.20"]))
    t.check("AAAA record", await udp_ask(port, "v6host.home", 28) == ("NOERROR", ["fd00::7"]))
    t.check("A record over TCP", await tcp_ask(port, "nas.home") == ("NOERROR", ["192.168.1.20"]))
    t.check("unknown host in our zone is NXDOMAIN", (await udp_ask(port, "missing.home"))[0] == "NXDOMAIN")
    await admin.run('/dns -append {"bing.com": "127.0.0.1"}')
    t.check("a hostname with dots overrides the public name", await udp_ask(port, "bing.com") == ("NOERROR", ["127.0.0.1"]))
    t.check("and is also reachable in the zone", await udp_ask(port, "bing.com.home") == ("NOERROR", ["127.0.0.1"]))
    www = await udp_ask(port, "www.bing.com")
    t.check("names it doesn't hold exactly are still forwarded", www[0] == "NOERROR" and "127.0.0.1" not in www[1], str(www))
    fwd = await udp_ask(port, "example.com")
    if fwd[0] == "SERVFAIL":  # the upstream server (on the internet) was slow; try once more
        fwd = await udp_ask(port, "example.com")
    t.check("other names are forwarded upstream", fwd[0] == "NOERROR" and fwd[1], str(fwd))
    refusing = DNSServer(lambda name: Lookup(REFUSED), upstream=None)
    rport = await refusing.start("127.0.0.1", (5313,))
    t.check("without an upstream, other names are refused", (await udp_ask(rport, "example.com"))[0] == "REFUSED")
    refusing.close()

    # --- node hostnames ---
    await wait(lambda: admin.api.public_ip and bob.api.public_ip, 60)
    na, nb = node_hostname(admin.net.me), node_hostname(bob.net.me)
    await wait(lambda: nb in dns_entries(admin, True) and na in dns_entries(bob, True), 20)
    t.check("every node gets an automatic hostname on its public IP",
            dns_entries(admin, True).get(nb) == bob.api.public_ip and dns_entries(bob, True).get(na) == admin.api.public_ip)

    await admin.run("/dns -assign bobby Bob")
    await wait(lambda: "bobby" in dns_entries(admin), 10)
    row = dns_a.dns_map.get("bobby") or {}
    t.check("an assigned hostname is published by its node, with no action from the user",
            row.get("ip") == bob.api.public_ip and row.get("updated_by") == bob.net.me)

    # --- SRV ---
    out = await bob.run("/dns -srv bobby minecraft tcp 25565")
    t.check("a node can add a service port to its own hostname", "port 25565" in out, out)
    await wait(lambda: dns_a.services_of("bobby"), 10)
    srv_answer = await udp_ask(port, "_minecraft._tcp.bobby.home", 33, with_additional=True)
    t.check("SRV query returns the port and target, with the target's IP added",
            srv_answer == ("NOERROR", [(0, 0, 25565, "bobby.home")], [LAN]), str(srv_answer))
    t.check("SRV query by bare name works too",
            (await udp_ask(port, "_minecraft._tcp.bobby", 33))[1] == [(0, 0, 25565, "bobby.home")])
    t.check("A lookups are unaffected by services", await udp_ask(port, "bobby.home") == ("NOERROR", [LAN]))
    t.check("a host without that service answers 'no records' (clients fall back to the default port)",
            await udp_ask(port, "_minecraft._tcp.nas.home", 33) == ("NOERROR", []))
    t.check("a host without any services still resolves normally", await udp_ask(port, "nas") == ("NOERROR", ["192.168.1.20"]))
    t.check("SRV for an unknown host is NXDOMAIN", (await udp_ask(port, "_minecraft._tcp.nobody.home", 33))[0] == "NXDOMAIN")
    t.check("SRV over TCP", (await tcp_ask(port, "_minecraft._tcp.bobby.home", 33))[1] == [(0, 0, 25565, "bobby.home")])

    out = await bob.run("/dns -srv nas minecraft tcp 25565")
    t.check("a member can't add services to someone else's hostname", out.startswith("! you may not"), out)
    out = await admin.run("/dns -srv nas web tcp 99999")
    t.check("invalid ports are refused", "invalid port" in out, out)
    out = await admin.run("/dns -srv ghost web tcp 80")
    t.check("a hostname needs an IP before it can have services", "set that first" in out, out)

    bob.api.public_ip = "203.0.113.50"
    await bob.net.handle({"event": "public_ip", "ip": "203.0.113.50"})
    await wait(lambda: dns_entries(admin, True).get(nb) == dns_entries(admin).get("bobby") == "203.0.113.50", 10)
    t.check("an IP change moves all of a node's hostnames",
            dns_entries(admin, True).get(nb) == dns_entries(admin).get("bobby") == "203.0.113.50")
    t.check("and keeps their services", [s["port"] for s in dns_a.services_of("bobby")] == [25565])

    await bob.run("/dns -unsrv bobby minecraft tcp")
    await wait(lambda: not dns_a.services_of("bobby"), 10)
    t.check("removing a service makes SRV queries fall back again",
            await udp_ask(port, "_minecraft._tcp.bobby.home", 33) == ("NOERROR", []))

    out = await bob.run(f"/dns -append {na} 6.6.6.6")
    t.check("a member can't set someone else's automatic hostname", out.startswith("! you may not"), out)
    out = await admin.run("/dns -assign n-custom Bob")
    t.check("'n-' names are reserved", "reserved" in out, out)

    await admin.run("/dns -assign bobby Admin")
    await wait(lambda: dns_entries(bob).get("bobby") == admin.api.public_ip, 10)
    t.check("reassigning moves the hostname and takes the old node's right away",
            dns_entries(bob).get("bobby") == admin.api.public_ip and not dns_b.may_update("bobby"))
    t.check("the DNS server answers assigned and automatic names",
            await udp_ask(port, f"{nb}.home") == ("NOERROR", [LAN])
            and await udp_ask(port, "bobby.home") == ("NOERROR", [LAN]))

    # --- which address: LAN IP or public IP ---
    row = dns_a.dns_map.get(nb)
    t.check("a node publishes its LAN IP with its public IP", row.get("lan") == LAN and row["ip"] == "203.0.113.50",
            str(row))
    t.check("Hyperswarm connected the two over the LAN (what 'same LAN' is judged by)",
            admin.net.addresses.get(bob.net.me) == LAN, str(admin.net.addresses))
    t.check("a node on the same LAN is answered with its LAN IP", await udp_ask(port, nb) == ("NOERROR", [LAN]))
    t.check("this node's own hostname is answered with its LAN IP", await udp_ask(port, na) == ("NOERROR", [LAN]))
    admin.net.addresses[bob.net.me] = "198.51.100.9"  # as if bob's connection came over the internet
    t.check("a node elsewhere is answered with its public IP",
            await udp_ask(port, nb) == ("NOERROR", ["203.0.113.50"]))
    admin.net.addresses[bob.net.me] = "192.168.1.250"  # a LAN address, but not the one bob published
    t.check("so is one whose published LAN IP isn't where its connection comes from",
            await udp_ask(port, nb) == ("NOERROR", ["203.0.113.50"]))
    admin.net.addresses[bob.net.me] = LAN
    t.check("hostnames set by hand are answered as set", await udp_ask(port, "nas") == ("NOERROR", ["192.168.1.20"]))
    t.check("a LAN address must be one", "isn't a LAN address" in (dns_a.validate_record(
        "dns_map", admin.net._clean_record("dns.dns_map", {**row, "lan": "8.8.8.8"}), bob.net.me) or ""))

    bob.api.firewalled = True  # what the sidecar reports behind NAT
    await bob.net.handle({"event": "public_ip", "ip": "203.0.113.50", "firewalled": True})
    await wait(lambda: (dns_a.dns_map.get(nb) or {}).get("firewalled") is True, 10)
    t.check("a node publishes when inbound connections to it are blocked",
            (dns_a.dns_map.get(nb) or {}).get("firewalled") is True)
    out = await admin.run("/dns -list")
    t.check("/dns -list shows LAN IPs, NAT, and what this node answers",
            f"LAN {LAN}" in out and "behind NAT" in out and "same LAN as this node" in out, out)
    out = await bob.run("/netuser -info")
    t.check("/netuser -info shows your LAN IP and whether inbound is blocked",
            f"LAN IP:    {LAN}" in out and "inbound:   blocked" in out, out)

    await admin.run("/network -leave")
    t.check("a network's names are still answered from disk after leaving it",
            await udp_ask(port, "nas.home") == ("NOERROR", ["192.168.1.20"]))
    t.check("from disk, this node's own name is still its LAN IP, others' their public IP",
            await udp_ask(port, f"{na}.home") == ("NOERROR", [LAN])
            and await udp_ask(port, f"{nb}.home") == ("NOERROR", ["203.0.113.50"]))

    for node in (admin, bob):
        await node.close()

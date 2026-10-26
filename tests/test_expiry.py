"""Cleaning up after nodes that are gone: their automatic hostnames expire
when they haven't been re-signed for 90 days, and their ledger rows after 180
days without being seen. Hostnames set by hand stay. Months passing is acted
out by moving the clock forward."""

import asyncio
from datetime import timedelta

import core.network
from core import storage
from modules.dns import node_hostname
from tests.harness import dns_entries, fresh_dir, network_of, wait


async def run(t):
    base = fresh_dir("expiry")
    delay, core.network.MAINTENANCE_DELAY = core.network.MAINTENANCE_DELAY, 10 ** 6  # tests run upkeep by hand
    try:
        await scenario(t, base)
    finally:
        storage.CLOCK_OFFSET = timedelta(0)
        core.network.MAINTENANCE_DELAY = delay


async def scenario(t, base):
    admin, bob, carol = await network_of(base, "admin", "bob", "carol")
    for node in (admin, bob):
        node.ctl.api.public_ip = None  # so the test decides what's published, not the real DHT
    names = {n.name: node_hostname(n.net.me) for n in (admin, bob, carol)}
    await carol.module("dns").set_dns(names["carol"], "10.0.0.3")
    await bob.module("dns").set_dns(names["bob"], "10.0.0.2")
    await admin.run("/dns -append nas 192.168.1.20")
    await wait(lambda: {names["carol"], names["bob"], "nas"} <= set(dns_entries(admin, True)), 10)
    carol_key = carol.net.me
    await carol.close()

    # --- 100 days later ---
    storage.CLOCK_OFFSET = timedelta(days=100)
    bob.ctl.api.public_ip = "10.0.0.2"  # bob is still here, with the same IP
    await bob.net.maintain()
    await asyncio.sleep(2)
    await admin.net.maintain()
    on_admin = dns_entries(admin, True)
    t.check("a gone node's hostname expires after 90 days", names["carol"] not in on_admin, str(on_admin))
    t.check("a node that's still around re-signs its own, so it stays", on_admin.get(names["bob"]) == "10.0.0.2",
            f"{on_admin.get(names['bob'])}, on bob: {bob.module('dns').dns_map.get(names['bob'])}")
    t.check("hostnames set by hand never expire", on_admin.get("nas") == "192.168.1.20")
    t.check("the gone node's ledger row is kept for now (180 days)", admin.net.ledger.get(carol_key) is not None)

    # A node that hasn't run its upkeep yet still has the old record; it isn't taken back.
    stale = bob.module("dns").dns_map.get(names["carol"])
    rec = {k: v for k, v in stale.items() if k != "deleted"} if stale else None
    if rec:
        await admin.net.receive(bob.net.me, {"dns.dns_map": {"data": [rec]}})
    t.check("an expired record that comes back from another node is refused",
            names["carol"] not in dns_entries(admin, True))

    # --- 200 days later ---
    storage.CLOCK_OFFSET = timedelta(days=200)
    await admin.net.maintain()
    t.check("after 180 days a gone node's ledger row is dropped", admin.net.ledger.get(carol_key) is None)
    t.check("nodes that are online keep theirs", admin.net.ledger.get(bob.net.me) is not None)
    await admin.net.receive(bob.net.me, {"node_ledger": {"data": [{"identity": carol_key, "alias": "Carol",
                                                                    "first_con": "2020-01-01T00:00:00+00:00",
                                                                    "last_con": "2020-01-02T00:00:00+00:00"}]}})
    t.check("and an expired row that comes back is refused", admin.net.ledger.get(carol_key) is None)

    # A node back after months away starts its record over (serial 1); a peer that
    # still holds its old, expired record must take the new one anyway.
    host = names["bob"]
    store = bob.module("dns").dns_map
    old = store.get(host)  # signed on day 100, so expired by day 300
    admin.net._store_record("dns.dns_map", admin.net._clean_record("dns.dns_map", old))  # admin hasn't purged it yet
    storage.CLOCK_OFFSET = timedelta(days=300)
    store.remove(host)  # what bob's own upkeep does with its expired copy
    await bob.module("dns").set_dns(host, "10.0.0.22")
    await wait(lambda: dns_entries(admin, True).get(host) == "10.0.0.22", 10)
    t.check("a returning node's restarted record replaces the expired one",
            dns_entries(admin, True).get(host) == "10.0.0.22" and int(old["serial"]) > 1,
            f"{dns_entries(admin, True).get(host)} (old serial {old['serial']})")

    for node in (admin, bob):
        await node.close()

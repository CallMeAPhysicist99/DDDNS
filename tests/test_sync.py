"""Core sync: pushes, signatures, forgeries, catching up from members, removals,
block/unblock and the shared ledger. Uses the dns module as the data to sync."""

import asyncio

from tests.harness import Node, dns_entries, fresh_dir, network_of, wait


async def run(t):
    base = fresh_dir("sync")
    admin, mia, max_ = await network_of(base, "admin", "mia", "max")
    t.check("three nodes form a full mesh", all(len(n.net.online) == 2 for n in (admin, mia, max_)))

    await admin.run('/dns -append {"NAS": "192.168.1.20", "printer": "192.168.1.30"}')
    want = {"nas": "192.168.1.20", "printer": "192.168.1.30"}
    await wait(lambda: dns_entries(max_) == want, 10)
    t.check("an admin's change reaches everyone (hostnames lowercased)", dns_entries(mia) == dns_entries(max_) == want)

    out = await mia.run("/dns -append nas 1.1.1.1")
    t.check("a member without a delegation is refused", out.startswith("! you may not update"), out)

    # Max signs a record he isn't allowed to and pushes it past the CLI.
    net = max_.net
    rec = net._clean_record("dns.dns_map", {"hostname": "nas", "ip": "6.6.6.6", "serial": 99,
                                            "last_modified": "z", "updated_by": net.me})
    rec["signature"] = await max_.api.sign(net._record_payload("dns.dns_map", rec))
    net._push({"dns.dns_map": {"data": [rec], "partial": True}})
    await asyncio.sleep(2)
    t.check("a forged DNS record is rejected", dns_entries(admin)["nas"] == dns_entries(mia)["nas"] == "192.168.1.20",
            next((n for n in admin.notes if "ignored" in n), ""))
    max_.net._store_record("dns.dns_map", admin.net._clean_record("dns.dns_map", admin.module("dns").dns_map.get("nas")))

    # Mia forges a newer blocklist that blocks the admin.
    blocklist = mia.net.blocklist
    blocklist.upsert(admin.net.me, alias="Admin")
    blocklist.stamp(version=50, last_modified="z", modified_by=mia.net.me, signature="00" * 64)
    mia.net._push({"blocklist": blocklist.envelope()})
    await asyncio.sleep(2)
    t.check("a forged blocklist is rejected", admin.net.me not in admin.net.blocklist and admin.net.me not in max_.net.blocklist)
    blocklist.replace(admin.net.blocklist.envelope())

    await admin.run("/dns -delegate nas Mia")
    await asyncio.sleep(1)
    await mia.run("/dns -append nas 192.168.1.21")
    await wait(lambda: dns_entries(max_)["nas"] == "192.168.1.21", 10)
    t.check("a delegated member's update reaches everyone", dns_entries(admin)["nas"] == dns_entries(max_)["nas"] == "192.168.1.21")

    await max_.run("/network -leave")
    await asyncio.sleep(3)
    await admin.run("/dns -remove printer")
    await admin.run("/network -set_name Home Net")
    await admin.run("/admin -append Mia")
    await asyncio.sleep(1)
    await admin.run("/network -leave")
    await asyncio.sleep(3)
    await mia.run("/dns -append git 10.0.0.8")  # Mia is an admin now
    await max_.run("1")
    secs = await wait(lambda: max_.net.name == "Home Net" and "git" in dns_entries(max_), 60)
    t.check("a rejoining member catches up from a member while the admin is offline",
            dns_entries(max_) == {"nas": "192.168.1.21", "git": "10.0.0.8"} and max_.net.is_admin(mia.net.me), f"{secs}s")
    t.check("a removed entry doesn't come back", "printer" not in dns_entries(max_))

    await admin.run("1")
    secs = await wait(lambda: "git" in dns_entries(admin), 60)
    t.check("an admin rejoining behind takes the newer data", "git" in dns_entries(admin) and admin.net.name == "Home Net", f"{secs}s")

    await wait(lambda: max_.net.me in admin.net.trusted_peers(), 60)  # Max may still be reconnecting
    await admin.run("/blocklist -append Max")
    dropped = await wait(lambda: max_.net.me not in admin.net.online, 15)
    told = any("you were blocked" in n for n in max_.notes)
    await admin.run("/blocklist -remove Max")
    back = await wait(lambda: max_.net.me in admin.net.online, 60)
    t.check("a blocked node is dropped and told why", dropped < 15 and told, f"{dropped}s")
    t.check("an unblocked node reconnects", max_.net.me in admin.net.online, f"{back}s")

    max_key = max_.net.me
    await wait(lambda: len(max_.net.trusted_peers()) == 2, 60)  # connected to both again
    await max_.run("/netuser -set_alias Maxi")
    await wait(lambda: (admin.net.ledger.get(max_key) or {}).get("alias") == "Maxi", 15)
    await max_.run("/network -leave")
    await asyncio.sleep(4)
    zoe = await Node(base, "zoe").start()
    await zoe.run(f"/join {admin.net.topic}", "Zoe")
    secs = await wait(lambda: (zoe.net.ledger.get(max_key) or {}).get("alias") == "Maxi", 60)
    t.check("a newcomer learns about an offline node from the ledger",
            (zoe.net.ledger.get(max_key) or {}).get("alias") == "Maxi", f"{secs}s")

    for node in (admin, mia, max_, zoe):
        await node.close()

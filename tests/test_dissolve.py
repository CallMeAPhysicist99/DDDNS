"""Dissolving a network: an admin closes it for everyone online, who leave and
delete it; it can't be rejoined. Also: settings signed before a setting
existed still verify (optional settings aren't added on load)."""

import json

from core.storage import NetworkSettings
from tests.harness import dns_entries, fresh_dir, network_of, wait


async def run(t):
    base = fresh_dir("dissolve")

    # Old settings files must come back exactly as they were signed.
    old = base / "old_settings.json"
    old_data = {"Topic": "home:" + "a" * 64, "Name": "home", "allowlist": 0}
    old.write_text(json.dumps({"version": 1, "data": old_data}))
    t.check("settings without the newer optional fields load unchanged (so their signature still holds)",
            NetworkSettings(old).envelope()["data"] == old_data)

    admin, bob, carol = await network_of(base, "admin", "bob", "carol")
    topic = admin.net.topic
    await admin.run("/dns -append nas 192.168.1.20")
    await wait(lambda: "nas" in dns_entries(carol), 10)

    out = await bob.run("/network -dissolve", "dissolve")
    t.check("members can't dissolve a network", "is for admins only" in out, out)
    out = await admin.run("/network -dissolve", "no")
    t.check("it needs confirmation", out.strip() == "cancelled" and admin.net is not None, out)

    out = await admin.run("/network -dissolve", "dissolve")
    t.check("an admin can dissolve it", "dissolved 'home'" in out and admin.net is None, out)
    secs = await wait(lambda: all(topic in n.identity.dissolved for n in (bob, carol)), 15)
    t.check("every online member leaves", bob.net is None and carol.net is None, f"{secs}s")
    t.check("and is told who dissolved it", any("Admin dissolved the network 'home'" in n for n in bob.notes))

    folders = [list((n.dir / "saved_networks").glob("home_*")) for n in (admin, bob, carol)]
    t.check("its data is deleted on every node", folders == [[], [], []], str(folders))
    t.check("it's gone from every node's saved networks",
            all(not n.identity.networks and topic in n.identity.dissolved for n in (admin, bob, carol)))

    out = await bob.run(f"/join {topic}", "Bob")
    t.check("it can't be rejoined", "dissolved by its admins" in out, out)
    out = await admin.run("/create home", "Admin")
    t.check("its creator can't recreate it under the same name by accident", "pick another name" in out, out)
    out = await carol.run("/show")
    t.check("/show no longer lists it", "haven't joined any networks" in out, out)

    for node in (admin, bob, carol):
        await node.close()

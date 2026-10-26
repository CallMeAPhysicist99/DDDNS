"""Network passwords: chosen at /create, stored only as a hash, checked by
members on every new connection, and never changeable (dissolve and create a
new network instead). Also /show."""

import asyncio

from core import auth
from tests.harness import Node, dns_entries, fresh_dir, wait


async def run(t):
    base = fresh_dir("password")
    admin = await Node(base, "admin").start()
    out = await admin.run("/create home", "Admin", "s3cret-pw")
    t.check("a password can be chosen when creating a network", "need the password too" in out, out)
    t.check("the network has it from the start", admin.net.requires_password and admin.net.settings.version == 1)
    await admin.run("/dns -append nas 192.168.1.20")
    await asyncio.sleep(6)
    topic = admin.net.topic

    settings_file = next((admin.dir / "saved_networks").rglob("network_settings.json")).read_text()
    t.check("the password isn't stored in plain text anywhere",
            "s3cret-pw" not in settings_file and "s3cret-pw" not in (admin.dir / "identity.json").read_text())
    t.check("network_settings.json holds a salted hash", '"salt"' in settings_file and '"hash"' in settings_file)

    bob = await Node(base, "bob").start()
    await bob.run(f"/join {topic}", "Bob", "s3cret-pw")
    secs = await wait(lambda: "nas" in dns_entries(bob), 60)
    t.check("the right password gets a node in, and it syncs", "nas" in dns_entries(bob), f"{secs}s")
    t.check("it's told the password was accepted", any("password accepted" in n for n in bob.notes))
    entry = bob.identity.network(topic)
    t.check("it remembers a derived key, not the password",
            entry.get("password_key") and "s3cret-pw" not in (bob.dir / "identity.json").read_text())

    carol = await Node(base, "carol").start()
    await carol.run(f"/join {topic}", "Carol", "wrong-pw")
    await wait(lambda: any("password is wrong" in n for n in carol.notes), 30)
    await asyncio.sleep(2)
    t.check("a wrong password is refused and the user is told", any("password is wrong" in n for n in carol.notes))
    t.check("and that node gets no data at all", "nas" not in dns_entries(carol) and not carol.net.requires_password)
    t.check("the members don't treat it as one of them",
            carol.net.me not in admin.net.trusted_peers() and carol.net.me not in bob.net.trusted_peers())
    await carol.run("/network -password", "s3cret-pw")
    secs = await wait(lambda: "nas" in dns_entries(carol), 60)
    t.check("/network -password lets a node retry with the right one", "nas" in dns_entries(carol), f"{secs}s")

    await bob.run("/exit")
    await bob.run("1")
    secs = await wait(lambda: bob.net.me in admin.net.trusted_peers() and admin.net.me in bob.net.trusted_peers(), 60)
    t.check("rejoining later works without typing it again",
            bob.net.me in admin.net.trusted_peers() and admin.net.me in bob.net.trusted_peers(), f"{secs}s")

    # --- it can't be changed ---
    out = await admin.run("/network -set_password")
    t.check("there's no command to change it", out.startswith("! /network needs one of"), out.splitlines()[0])
    # An admin going around the CLI: new password, signed and pushed like any setting.
    old = admin.net.settings["password"]
    admin.net.settings.update(password=auth.new_password("other-pw"))
    async with admin.net._lock:
        await admin.net._commit("network_settings")
    await wait(lambda: any("can't be changed" in n for n in bob.notes), 15)
    t.check("members refuse a changed password, even signed by an admin",
            bob.net.settings["password"] == old and carol.net.settings["password"] == old)
    t.check("and say why", any("can't be changed" in n for n in bob.notes))

    # --- changing it means a new network ---
    out = await admin.run("/network -dissolve", "dissolve")
    t.check("dissolving still works after the refused change", "dissolved 'home'" in out, out)
    # The admin's own copy now carries the refused password, so members refuse its
    # dissolve too; in real use an admin can't get into that state (no command for it).
    await wait(lambda: topic in bob.identity.dissolved and topic in carol.identity.dissolved, 15)
    for node in (bob, carol):
        if node.net:
            await node.run("/exit")
    await admin.run("/create home2", "Admin", "new-pw")
    await asyncio.sleep(6)
    await bob.run(f"/join {admin.net.topic}", "Bob", "new-pw")
    secs = await wait(lambda: bob.net.me in admin.net.trusted_peers(), 60)
    t.check("to change it: dissolve, then create a new network with the new password",
            bob.net.me in admin.net.trusted_peers() and bob.net.requires_password, f"{secs}s")

    # --- /show ---
    out = await carol.run("/show")
    t.check("/show lists saved networks when off-network", "haven't joined" in out or "Type a number" in out, out)
    out = await admin.run("/show")
    t.check("/show marks the current one when on a network", "home2" in out and "you're here" in out, out)

    for node in (admin, bob, carol):
        await node.close()

"""The module system: nodes with different modules on one network, module
commands and their admin/member rules, and the /module enabler."""

import asyncio

from core.storage import Config
from tests.harness import Node, fresh_dir, network_of, wait


async def run(t):
    base = fresh_dir("modules")
    admin, = await network_of(base, "admin")
    plain = await Node(base, "plain", modules=[]).start()  # the bare core, no modules
    await plain.run(f"/join {admin.net.topic}", "Plain")
    await wait(lambda: len(plain.net.online) == 1, 60)
    t.check("a node with no modules joins and syncs the core", plain.net.name == "home" and len(plain.net.online) == 1)

    await admin.run("/dns -append nas 192.168.1.20")
    await asyncio.sleep(2)
    await admin.run("/dns -append printer 192.168.1.30")
    await asyncio.sleep(2)
    missing = [n for n in plain.notes if "'dns' module" in n]
    t.check("it's told once that the network uses a module it doesn't run", len(missing) == 1, missing[0] if missing else "")
    t.check("and the message says how to enable it", missing and "/module -enable dns" in missing[0])
    t.check("its network folder has no DNS files", not any(p.name.startswith("dns") for p in (plain.dir / "saved_networks").rglob("*.json")))

    out = await plain.run("/dns -list")
    t.check("commands of modules it doesn't run don't exist", out.startswith("! unknown command /dns"), out)
    help_plain, help_admin = await plain.run("/help"), await admin.run("/help")
    t.check("/help shows only the core without modules", "/dns" not in help_plain and "/network -info" in help_plain)
    t.check("/help shows module commands with their admin marks",
            "A /dns -assign" in help_admin and "  /dns -append" in help_admin and "/broadcast" in help_admin)

    member = await Node(base, "member").start()
    await member.run(f"/join {admin.net.topic}", "Member")
    await wait(lambda: len(member.net.online) == 2, 60)
    out = await member.run("/dns -assign web Admin")
    t.check("an admin-only module command is refused for members", "is for admins only" in out, out)

    await member.run("/dm Admin hello there")
    await member.run("/broadcast hi all")
    await asyncio.sleep(2)
    t.check("chat module: direct message", any("[DM] <Member> hello there" in n for n in admin.notes))
    t.check("chat module: broadcast", any("<Member> hi all" in n for n in admin.notes))
    t.check("a node without chat is told about that module too", any("'chat' module" in n for n in plain.notes))

    # --- /exit ---
    topic = member.net.topic
    out = await member.run("/exit")
    t.check("/exit leaves the network and shows the menu", member.net is None and "Your networks:" in out, out)
    await wait(lambda: member.ctl.api.public_key not in admin.net.online, 10)
    t.check("the others see the node leave", member.ctl.api.public_key not in admin.net.online)
    t.check("the program keeps running", member.ctl.running)
    out = await member.run("/exit")
    t.check("/exit off-network says to join first", "join or create a network first" in out, out)
    await member.run("1")
    await wait(lambda: member.net and len(member.net.online) == 2, 60)
    t.check("and the node can join again afterwards", member.net.topic == topic and len(member.net.online) == 2)

    # --- the enabler ---
    out = await admin.run("/module -list")
    t.check("/module -list shows the modules", "dns" in out and "running" in out, out.splitlines()[0])
    out = await admin.run("/module -disable dns")
    t.check("a module others need can't be disabled", "ddns need" in out, out)
    await admin.run("/module -disable ddns")
    await admin.run("/module -disable dns")
    t.check("disabling is saved to config.json", Config(admin.dir / "config.json", []).modules == ["chat"])
    out = await admin.run("/module -enable ddns")
    t.check("enabling a module also enables what it needs", Config(admin.dir / "config.json", []).modules == ["chat", "dns", "ddns"], out)
    out = await admin.run("/module -enable nope")
    t.check("unknown modules are refused", out.startswith("! no module"), out)

    for node in (admin, plain, member):
        await node.close()

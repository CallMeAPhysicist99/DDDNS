"""Failures that mustn't take the node down: a crashing sidecar, a module that
throws, and modules whose names would collide."""

import asyncio

from core.module import Module, RecordFile, command, commands_of
from tests.harness import Node, dns_entries, fresh_dir, wait


class BrokenModule(Module):
    """Throws from every hook it has."""
    name = "broken"
    files = [RecordFile("broken_things", key="id", fields=("value",))]

    async def on_message(self, peer, kind, data):
        raise RuntimeError("on_message exploded")

    async def on_records(self, file_name, records, from_peer):
        raise RuntimeError("on_records exploded")

    def describe_record(self, file_name, rec):
        raise RuntimeError("describe exploded")

    @command("broken", "crash", needs_network=False, help="raises")
    def cmd_crash(self, arg):
        raise RuntimeError("command exploded")


class ClashingFile(Module):
    name = "clash1"
    files = [RecordFile("admins", key="id")]


class ClashingCommand(Module):
    name = "clash2"

    @command("dns", "list", help="same as the dns module's")
    def cmd_list(self, arg):
        pass


class ClashingModuleFile(Module):
    name = "clash3"
    files = [RecordFile("dns_map", key="hostname")]


async def node_with_broken(base, name) -> Node:
    node = await Node(base, name, modules=["dns", "chat"]).start()
    broken = BrokenModule(node.ctl)
    node.ctl.modules["broken"] = broken  # before joining, so the network loads its files
    node.ctl.commands += commands_of(broken)
    return node


async def run(t):
    base = fresh_dir("robustness")

    # --- a module that throws ---
    admin = await node_with_broken(base, "admin")
    await admin.run("/create home", "Admin")
    await asyncio.sleep(6)
    bob = await node_with_broken(base, "bob")
    await bob.run(f"/join {admin.net.topic}", "Bob")
    await wait(lambda: len(admin.net.online) == 1 and len(bob.net.online) == 1, 60)

    await admin.ctl.modules["broken"].write_record("broken_things", "a", value="1")
    await admin.run("/dns -append nas 192.168.1.20")
    await wait(lambda: "nas" in dns_entries(bob), 10)
    t.check("a module failing in on_records is reported",
            any("module 'broken' failed in on_records" in n for n in bob.notes))
    t.check("and the other modules still get their data", dns_entries(bob).get("nas") == "192.168.1.20")

    bob.net.send_module_message(admin.net.me, "broken.boom", {})
    await bob.run("/dm Admin still here")
    await asyncio.sleep(2)
    t.check("a module failing in on_message is reported", any("failed in on_message" in n for n in admin.notes))
    t.check("and messages for other modules still arrive", any("still here" in n for n in admin.notes))

    out = await admin.run("/broken -crash")
    t.check("a command that raises is reported, not fatal", out.startswith("! that command failed"), out)

    # --- an idle network stays quiet (the ledger once bounced between nodes forever) ---
    await asyncio.sleep(5)  # let joining settle
    sent = []
    real_send = admin.api.send
    admin.api.send = lambda peer, data: (sent.append(data.get("type")), real_send(peer, data))[1]
    await asyncio.sleep(8)
    admin.api.send = real_send
    t.check("two idle nodes send each other (almost) nothing", len(sent) <= 2, f"{len(sent)} messages in 8s")

    # --- name collisions ---
    t.check("a module file named like a core file is refused",
            "admins.json would overwrite" in (admin.ctl._conflict(ClashingFile(admin.ctl)) or ""))
    t.check("a module command that already exists is refused",
            "/dns -list already exists" in (admin.ctl._conflict(ClashingCommand(admin.ctl)) or ""))
    t.check("a module file named like another module's is refused",
            "dns_map.json would overwrite" in (admin.ctl._conflict(ClashingModuleFile(admin.ctl)) or ""))

    # --- the sidecar dies ---
    bob.api._proc.kill()
    secs = await wait(lambda: any("stopped unexpectedly" in n for n in bob.notes), 10)
    t.check("a crashed sidecar is noticed", any("stopped unexpectedly" in n for n in bob.notes), f"{secs}s")
    t.check("and the command loop is told to end", bob.ctl.running is False)
    start = asyncio.get_running_loop().time()
    out = await bob.run(f"/dns -append n-{bob.net.me[:12]} 10.0.0.1")  # his own name: allowed, needs a signature
    took = asyncio.get_running_loop().time() - start
    t.check("commands that need it fail fast instead of hanging",
            out.startswith("! ") and "isn't running" in out and took < 2, f"{out} ({took:.1f}s)")

    for node in (admin, bob):
        await node.close()

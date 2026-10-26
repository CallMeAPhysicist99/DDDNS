"""Limits on what one peer can make another node do: too many messages, a
message that's too big, data with bad signatures. Each misbehaving member is
cut off; everyone else stays connected."""

import asyncio

from core.storage import now
from modules.dns import node_hostname
from tests.harness import fresh_dir, network_of, wait


def limited(node, who: str) -> bool:
    return any(who in n and "disconnected" in n for n in node.notes)


async def run(t):
    base = fresh_dir("limits")
    admin, bob, carol, dave = await network_of(base, "admin", "bob", "carol", "dave")
    me = admin.net.me

    # --- data with bad signatures (checking each one costs time) ---
    fake = [{"hostname": node_hostname(carol.net.me), "ip": "10.0.0.1", "serial": 100 + i,
             "last_modified": now(), "updated_by": carol.net.me, "signature": "00" * 64}
            for i in range(30)]
    carol.api.send(me, {"type": "sync", "files": {"dns.dns_map": {"data": fake}}})
    await wait(lambda: limited(admin, "Carol"), 15)
    t.check("a peer sending data with bad signatures is cut off", limited(admin, "Carol")
            and any("bad signatures" in n for n in admin.notes))
    t.check("and none of it is used", admin.module("dns").dns_map.get(node_hostname(carol.net.me)) is None
            or admin.module("dns").dns_map.get(node_hostname(carol.net.me))["ip"] != "10.0.0.1")

    # --- too many messages ---
    for _ in range(3000):
        bob.api.send(me, {"type": "chat.broadcast", "text": "spam"})
    await wait(lambda: limited(admin, "Bob"), 20)
    t.check("a peer flooding messages is cut off", limited(admin, "Bob")
            and any("messages a second" in n for n in admin.notes))
    spam = sum("spam" in n for n in admin.notes)
    t.check("most of the flood never reaches the node", spam < 1500, f"{spam} shown")

    # --- one huge message ---
    dave.api.send(me, {"type": "chat.dm", "text": "x" * (9 * 1024 * 1024)})
    await wait(lambda: limited(admin, "Dave"), 30)
    t.check("a peer sending a message over 8 MB is cut off", limited(admin, "Dave")
            and any("over 8" in n for n in admin.notes))

    await asyncio.sleep(10)  # time for them to try to reconnect
    t.check("peers cut off for a limit stay refused for a while",
            bob.net.me not in admin.net.online and dave.net.me not in admin.net.online, str(admin.net.online))
    t.check("the admin's node is still fine", admin.ctl.running and admin.api.alive)

    for node in (admin, bob, carol, dave):
        await node.close()

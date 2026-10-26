"""Succession: when no admin has been around for the network's succession
period, the longest-standing member takes over, and everyone checks that claim
for themselves. Weeks passing is acted out by moving the clock forward."""

from datetime import timedelta

import core.network
from core import storage
from tests.harness import Node, fresh_dir, network_of, wait


def keys(node) -> set:
    return set(node.net.admins.keys())


async def run(t):
    base = fresh_dir("succession")
    delay, core.network.MAINTENANCE_DELAY = core.network.MAINTENANCE_DELAY, 10 ** 6  # tests run upkeep by hand
    try:
        await scenario(t, base)
    finally:
        storage.CLOCK_OFFSET = timedelta(0)
        core.network.MAINTENANCE_DELAY = delay


async def scenario(t, base):
    admin, bob, carol = await network_of(base, "admin", "bob", "carol")
    topic = admin.net.topic
    t.check("the network's only admin is reminded to add another or keep a backup",
            any("only admin" in n for n in admin.notes))

    out = await bob.run("/network -succession 5")
    t.check("members can't change the succession setting", "admins only" in out, out)
    out = await admin.run("/network -info")
    t.check("/network -info shows succession (30 days by default)", "after 30 days" in out, out)

    # --- nobody takes over while an admin is around ---
    t.check("no member takes over while the admin is around",
            not await bob.net.check_succession() and not await carol.net.check_succession())

    # A claim made anyway is refused by everyone who saw the admin recently.
    saved = bob.net.admins.envelope()
    async with bob.net._lock:
        bob.net.admins.upsert(bob.net.me, alias="Bob")
        await bob.net._commit("admins")
    await wait(lambda: any("can't take over" in n for n in carol.notes), 10)
    t.check("a premature claim is refused (an admin was around)",
            bob.net.me not in keys(carol) and bob.net.me not in keys(admin)
            and any("was around less than 30 days" in n for n in carol.notes))
    bob.net.admins.replace(saved)  # undo it on bob too
    bob.net._after_change({"admins"})

    # --- the admin leaves; 40 days pass ---
    await admin.close()
    storage.CLOCK_OFFSET = timedelta(days=40)
    since = [{k: n.net.member_since(k) for k in (bob.net.me, carol.net.me)} for n in (bob, carol)]
    t.check("both members agree since when each has been a member", since[0] == since[1], str(since))
    for node in (bob, carol):
        await node.net.maintain()  # the hourly upkeep, where succession is checked
    claimed = [n for n in (bob, carol) if any("you took over as admin" in x for x in n.notes)]
    t.check("after 40 days without an admin, exactly one member takes over", len(claimed) == 1,
            [n.name for n in claimed])
    heir, other = (claimed[0], carol if claimed[0] is bob else bob) if claimed else (bob, carol)
    await wait(lambda: heir.net.me in keys(other), 10)
    t.check("the other member checks the claim and accepts it", other.net.is_admin(heir.net.me))
    t.check("and is told why", any("took over as admin (succession)" in n for n in other.notes))
    out = await heir.run("/network -set_name homenet")
    await wait(lambda: other.net.name == "homenet", 10)
    t.check("the new admin's changes are accepted", other.net.name == "homenet", out)

    # --- the old admin comes back ---
    admin = await Node(base, "admin").start()
    await admin.run(f"/join {topic}")
    await wait(lambda: heir.net.me in keys(admin), 90)
    t.check("the returning admin accepts the new admin (it was away)", admin.net.is_admin(heir.net.me),
            f"online: {len(admin.net.online)}; " + " | ".join(n for n in admin.notes if "!" in n or "admin" in n))
    await wait(lambda: other.net.admins.meta["modified_by"] == admin.net.me, 15)
    t.check("and confirms it by signing the admin list itself",
            heir.net.admins.meta["modified_by"] == admin.net.me == other.net.admins.meta["modified_by"]
            and heir.net.is_admin(heir.net.me))

    # --- succession can be turned off ---
    out = await admin.run("/network -succession off")
    await wait(lambda: other.net.settings.succession_days == 0, 10)
    t.check("an admin can turn succession off for everyone", other.net.settings.succession_days == 0, out)

    for node in (admin, bob, carol):
        await node.close()

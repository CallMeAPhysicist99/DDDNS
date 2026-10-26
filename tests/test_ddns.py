"""DDNS module: dyndns2 updates the way a Hikvision device sends them, on an
admin node and on a member node acting as gateway."""

from tests.harness import dns_entries, fresh_dir, http_get, network_of, wait


async def run(t):
    base = fresh_dir("ddns")
    admin, bob = await network_of(base, "admin", "bob", no_ddns=False, ddns_ports=[8091, 8092])
    port, port2 = admin.module("ddns").endpoint.port, bob.module("ddns").endpoint.port

    await admin.run("/ddns -adduser camera cam1", "s3cret")
    update = "/nic/update?system=dyndns&hostname=cam1.home&myip=192.168.1.64"
    t.check("camera update is accepted", await http_get(port, update, "camera", "s3cret") == ("200 OK", "good 192.168.1.64"))
    t.check("same IP again is 'nochg'", await http_get(port, update, "camera", "s3cret") == ("200 OK", "nochg 192.168.1.64"))
    t.check("no login gets a challenge", await http_get(port, update) == ("401 Unauthorized", "badauth"))
    t.check("wrong password is 'badauth'", (await http_get(port, update, "camera", "nope"))[1] == "badauth")
    t.check("a hostname the login doesn't own is 'nohost'",
            (await http_get(port, "/nic/update?hostname=nas.home&myip=1.2.3.4", "camera", "s3cret"))[1] == "nohost")
    t.check("another zone is 'nohost'",
            (await http_get(port, "/nic/update?hostname=cam1.other&myip=1.2.3.4", "camera", "s3cret"))[1] == "nohost")
    t.check("without myip the sender's address is used",
            (await http_get(port, "/nic/update?hostname=cam1.home", "camera", "s3cret"))[1] == "good 127.0.0.1")
    t.check("an invalid IP is 'dnserr'",
            (await http_get(port, "/nic/update?hostname=cam1.home&myip=999.1.1.1", "camera", "s3cret"))[1] == "dnserr")
    t.check("other paths are 404", (await http_get(port, "/admin", "camera", "s3cret"))[0] == "404 Not Found")

    await http_get(port, update, "camera", "s3cret")
    await wait(lambda: dns_entries(bob).get("cam1") == "192.168.1.64", 10)
    t.check("the update reaches the other node", dns_entries(bob).get("cam1") == "192.168.1.64")

    await bob.run("/ddns -adduser nvr cam2", "pw2")
    q = "/nic/update?hostname=cam2.home&myip=192.168.1.70"
    t.check("a member gateway is refused without a delegation", (await http_get(port2, q, "nvr", "pw2"))[1] == "nohost")
    await admin.run("/dns -delegate cam2 Bob")
    await wait(lambda: bob.module("dns").may_update("cam2"), 10)
    t.check("a member gateway works once delegated", (await http_get(port2, q, "nvr", "pw2"))[1] == "good 192.168.1.70")
    await wait(lambda: dns_entries(admin).get("cam2") == "192.168.1.70", 10)
    t.check("the gateway's update reaches the admin", dns_entries(admin).get("cam2") == "192.168.1.70")

    for node in (admin, bob):
        await node.close()

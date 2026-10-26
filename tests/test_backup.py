"""Identity backups: encrypted with a passphrase, restored on another device."""

import json

from core import backup
from core.storage import Identity
from tests.harness import Node, fresh_dir


async def run(t):
    base = fresh_dir("backup")

    # --- the format ---
    sealed = backup.seal({"seed": "ab" * 32}, "correct horse")
    t.check("the backup doesn't contain the seed in readable form", "abab" not in json.dumps(sealed))
    t.check("the right passphrase opens it", backup.unseal(sealed, "correct horse") == {"seed": "ab" * 32})
    for name, damaged, passphrase in (("a wrong passphrase", sealed, "wrong horse"),
                                      ("a changed file", {**sealed, "data": sealed["data"][:-4] + "AAA="}, "correct horse"),
                                      ("a file that isn't a backup", {"seed": "x"}, "correct horse")):
        try:
            backup.unseal(damaged, passphrase)
            t.check(f"{name} is detected", False)
        except ValueError:
            t.check(f"{name} is detected", True)

    # --- the commands ---
    old = await Node(base, "old").start()
    new = await Node(base, "new").start()
    file = base / "old-identity.backup"
    out = await old.run(f"/identity -export {file}", "short")
    t.check("a short passphrase is refused", "at least" in out and not file.exists(), out)
    out = await old.run(f"/identity -export {file}", "a long passphrase", "a different one")
    t.check("the passphrase must be typed the same twice", "don't match" in out and not file.exists(), out)
    out = await old.run(f"/identity -export {file}", "a long passphrase", "a long passphrase")
    t.check("an encrypted backup is written", file.exists() and "saved an encrypted backup" in out, out)

    out = await new.run(f"/identity -import {file}", "not the passphrase")
    t.check("importing with the wrong passphrase changes nothing",
            "wrong passphrase" in out and new.identity.seed != old.identity.seed, out)
    out = await new.run(f"/identity -import {file}", "a long passphrase", "no")
    t.check("importing needs confirmation", "cancelled" in out and new.identity.seed != old.identity.seed, out)
    replaced_seed = new.identity.seed
    out = await new.run(f"/identity -import {file}", "a long passphrase", "import")
    on_disk = Identity(new.dir / "identity.json")
    t.check("the backup's identity replaces this device's", on_disk.seed == old.identity.seed, out)
    kept = list(new.dir.glob("identity.replaced-*.json"))
    t.check("the replaced identity is kept next to it",
            len(kept) == 1 and json.loads(kept[0].read_text())["seed"] == replaced_seed)
    t.check("and the program closes so it restarts with the new key", new.ctl.running is False)

    for node in (old, new):
        await node.close()

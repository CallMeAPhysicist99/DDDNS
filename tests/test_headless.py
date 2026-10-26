"""Headless mode: main.py --headless as a real process, the way a service runs
it. It opens the saved network by itself, keeps it up and logs what happens."""

import asyncio
import sys
from pathlib import Path

from tests.harness import Node, fresh_dir, wait

ROOT = Path(__file__).parent.parent


async def headless(data: Path, *args: str) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        sys.executable, "main.py", "--headless", "--data", str(data), "--no-dns", "--no-ddns", *args,
        cwd=ROOT, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL)


async def finished(proc, timeout=30) -> tuple[int, str]:
    out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    return proc.returncode, out.decode(errors="replace")


async def run(t):
    base = fresh_dir("headless")

    # --- nothing to open ---
    code, out = await finished(await headless(base / "empty"))
    t.check("without a saved network it says so and stops (exit code 2)",
            code == 2 and "needs --network" in out, f"{code}: {out[-300:]}")

    admin = await Node(base, "admin").start()
    await admin.run("/create home", "Admin")
    topic, admin_key = admin.net.topic, admin.net.me
    await admin.close()
    code, out = await finished(await headless(base / "admin", "--network", "nosuch"))
    t.check("an unknown --network is refused", code == 2 and "no saved network 'nosuch'" in out, out[-300:])

    # --- a running node ---
    proc = await headless(base / "admin", "--network", "home")
    try:
        await asyncio.sleep(6)
        bob = await Node(base, "bob").start()
        await bob.run(f"/join {topic}", "Bob")
        secs = await wait(lambda: admin_key in bob.net.online, 60)
        t.check("it opens the network by itself and others can connect", admin_key in bob.net.online, f"{secs}s")
        await bob.run("/broadcast hello from bob")
        log = base / "admin" / "dddns.log"
        await wait(lambda: "hello from bob" in log.read_text(encoding="utf-8"), 10)
        text = log.read_text(encoding="utf-8")
        t.check("what happens is written to the log file",
                "Bob connected" in text and "hello from bob" in text, text[-500:])
        t.check("it isn't waiting for a keyboard (nobody types)", proc.returncode is None)
        await bob.close()
    finally:
        proc.kill()  # what a service manager does on Windows
        await proc.wait()

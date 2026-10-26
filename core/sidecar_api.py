"""Thin interface to sidecar/sidecar.js: start it, send commands, receive events.

Knows nothing about networks, roles or DNS - only peers, topics, JSON messages
and signatures. Runs on the asyncio event loop: no threads.

Sending (join, send, broadcast, firewall, ...) is a plain call that queues a
line for the sidecar. Anything that waits for an answer (start, sign, verify,
goodbye) is a coroutine.
"""

import asyncio
import inspect
import itertools
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

SIDECAR = Path(__file__).parent / "sidecar" / "sidecar.js"


def find_node() -> str:
    found = shutil.which("node")
    if found:
        return found
    default = Path(r"C:\Program Files\nodejs\node.exe")
    if default.exists():
        return str(default)
    raise RuntimeError("Node.js not found. Install it from nodejs.org")


class SidecarAPI:
    """Events (subscribe with @api.on(name), or "*" for all; handlers may be async):
        ready, joined, left, peer_connected (peer, ip, port), peer_disconnected,
        message (peer, data), peers, goodbye_sent, public_ip (ip, firewalled), error,
        peer_limited (peer, reason, minutes): a peer was cut off for breaking a limit,
        sidecar_died (code): the Node process exited without close() being called
    """

    def __init__(self, node: str | None = None):
        self._node = node or find_node()
        self._handlers: dict[str, list[Callable]] = {}
        self._proc: asyncio.subprocess.Process | None = None
        self._events: asyncio.Queue = asyncio.Queue()
        self._ids = itertools.count(1)
        self._pending: dict[int, asyncio.Future] = {}
        self._ready: asyncio.Future | None = None
        self._goodbye: asyncio.Future | None = None
        self._tasks: list[asyncio.Task] = []
        self.public_key: str | None = None
        self.public_ip: str | None = None  # as the DHT sees us; None until it knows
        self.firewalled = False  # inbound connections blocked (behind NAT/firewall, no forwarded port)
        self._closing = False

    async def start(self, seed: str, timeout: float = 15) -> str:
        """Start the sidecar and create the node from a 64-hex seed. Returns its public key."""
        self._proc = await asyncio.create_subprocess_exec(
            self._node, str(SIDECAR),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            limit=64 * 1024 * 1024,  # a full sync is one line (peers may send up to 8 MB of characters)
        )
        self._ready = asyncio.get_running_loop().create_future()
        self._tasks = [asyncio.create_task(self._read_loop()), asyncio.create_task(self._dispatch_loop())]
        self._send(cmd="init", seed=seed)
        try:
            self.public_key = await asyncio.wait_for(self._ready, timeout)
        except asyncio.TimeoutError:
            await self.close()
            raise RuntimeError("sidecar did not start (did you run `npm install` in sidecar/?)")
        return self.public_key

    # --- events -----------------------------------------------------------

    def on(self, event: str):
        """Decorator: @api.on("message") def handle(evt): ...  (or async def)"""
        def register(fn):
            self._handlers.setdefault(event, []).append(fn)
            return fn
        return register

    async def _read_loop(self):
        """Reads the sidecar's output. Answers (signed/verified) complete their
        waiting call right here; everything else is queued for the handlers, so
        a handler can await sign()/verify() without blocking this loop."""
        while line := await self._proc.stdout.readline():
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = evt.get("event")
            if name in ("signed", "verified"):
                future = self._pending.pop(evt.get("id"), None)
                if future and not future.done():
                    future.set_result(evt)
                continue
            if name == "ready" and not self._ready.done():
                self._ready.set_result(evt["publicKey"])
            elif name == "goodbye_sent" and self._goodbye and not self._goodbye.done():
                self._goodbye.set_result(True)
            elif name == "public_ip":
                self.public_ip = evt["ip"]
                self.firewalled = bool(evt.get("firewalled"))
            self._events.put_nowait(evt)

        # Output ended: the sidecar exited. Fail whatever is waiting for an answer,
        # and unless we're closing it on purpose, tell the handlers.
        code = await self._proc.wait()
        for future in self._pending.values():
            if not future.done():
                future.set_exception(RuntimeError("the network process (sidecar) stopped"))
        self._pending.clear()
        if not self._closing:
            self._events.put_nowait({"event": "sidecar_died", "code": code})

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def _dispatch_loop(self):
        while True:
            evt = await self._events.get()
            for fn in self._handlers.get(evt.get("event"), []) + self._handlers.get("*", []):
                try:
                    result = fn(evt)
                    if inspect.isawaitable(result):
                        await result
                except Exception:
                    # A failing handler must not stop event handling.
                    import traceback
                    traceback.print_exc(file=sys.stderr)

    # --- commands ---------------------------------------------------------

    def _send(self, **cmd):
        if self._proc and self._proc.returncode is None:
            self._proc.stdin.write((json.dumps(cmd) + "\n").encode())

    async def _request(self, timeout: float = 10, **cmd) -> dict:
        if not self.alive:
            raise RuntimeError("the network process (sidecar) isn't running")
        cmd["id"] = next(self._ids)
        future = asyncio.get_running_loop().create_future()
        self._pending[cmd["id"]] = future
        self._send(**cmd)
        try:
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            self._pending.pop(cmd["id"], None)
            raise TimeoutError(f"sidecar didn't answer '{cmd['cmd']}'")

    def join(self, topic: str):
        self._send(cmd="join", topic=topic)

    def leave(self, topic: str):
        self._send(cmd="leave", topic=topic)

    def send(self, peer: str, data: Any):
        self._send(cmd="send", peer=peer, data=data)

    def broadcast(self, data: Any):
        self._send(cmd="broadcast", data=data)

    def firewall(self, allow: list[str] | None, deny: list[str]):
        """allow=None accepts everyone not denied; deny always wins.
        Existing connections that no longer pass are dropped."""
        self._send(cmd="firewall", allow=allow, deny=deny)

    def disconnect(self, peer: str):
        self._send(cmd="disconnect", peer=peer)

    async def goodbye(self, topic: str, data: Any, timeout: float = 5):
        """Leave the topic, send `data` to every peer, close all connections."""
        if not self.alive:
            return
        self._goodbye = asyncio.get_running_loop().create_future()
        self._send(cmd="goodbye", topic=topic, data=data)
        try:
            await asyncio.wait_for(self._goodbye, timeout)
        except asyncio.TimeoutError:
            pass

    def list_peers(self):
        self._send(cmd="peers")

    async def sign(self, data: str) -> str:
        """Sign a string with this node's private key. Returns the signature as hex."""
        return (await self._request(cmd="sign", data=data))["signature"]

    async def verify(self, data: str, signature: str, public_key: str) -> bool:
        """True if `signature` is `public_key`'s signature of `data`."""
        return bool((await self._request(cmd="verify", data=data, signature=signature,
                                         publicKey=public_key))["ok"])

    async def close(self):
        self._closing = True
        if self._proc and self._proc.returncode is None:
            self._send(cmd="shutdown")
            try:
                await asyncio.wait_for(self._proc.wait(), 5)
            except asyncio.TimeoutError:
                self._proc.kill()
        for task in self._tasks:
            task.cancel()

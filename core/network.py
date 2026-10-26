"""One joined network: membership, roles, the ledger and data sync. Knows
nothing about DNS or any other module; modules plug in through core.module.

How data stays in sync
----------------------
  * Core files (admins, network_settings, allowlist, blocklist) are signed as a
    whole by the admin who changed them: version +1, signed, saved, pushed.
  * Module files are records signed one by one, and merged record by record
    (highest serial wins per key). The module's validate_record() decides who
    may write which record.
  * When two nodes connect, and on /network -sync, each sends ALL its files.
    A receiver takes what's newer (after checking signatures), forwards it to
    its other peers, and sends back what the sender is behind on.
  * Anyone can relay data, admin or not: what's checked is the signature of
    whoever made the change, not who delivered it.
  * node_ledger.json is not signed: every node writes its own observations,
    and rows are merged (newest last_con wins per node).
  * Files and messages for a module this node doesn't run are not used or
    relayed (they can't be checked); the user is told once which module.
  * If the network has a password, a connecting node gets nothing until it
    has answered a password challenge (see core.auth).

Upkeep (about once an hour, see maintain)
-----------------------------------------
  * Records a module lets expire (e.g. a node's own hostname) are dropped
    once nobody has re-signed them for that long, and refused if they come
    back. Ledger rows of nodes not seen for LEDGER_EXPIRY_DAYS go the same way.
  * Succession: when no admin has been around for the network's succession
    period (default 30 days), the longest-standing member that's around signs
    an admin list that adds itself (see check_succession). Every node checks
    that claim against its own records before accepting it.

Everything runs on the asyncio event loop. self._lock keeps a sync and a local
change from interleaving while one of them waits for a signature.
"""

import asyncio
import json
import re
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Awaitable, Callable

from core import auth
from core.module import Module, RecordFile
from core.sidecar_api import SidecarAPI
from core.storage import (AccessList, Admins, Identity, NetworkSettings, NodeLedger, RecordStore, SyncedFile,
                          days_ago, network_folder, now, parse_time)

ADMIN = "admin"
MEMBER = "member"

# Core files signed as a whole by an admin, in the order a received sync is processed:
# admins first, so a newly promoted admin's other changes are accepted in the same sync.
SIGNED_FILES = ("admins", "network_settings", "allowlist", "blocklist")
LEDGER = "node_ledger"
CORE_FILES = (*SIGNED_FILES, LEDGER, "this_node_blocklist")  # file names modules can't use
LEDGER_PUSH_DELAY = 3  # seconds; ledger changes within this window are pushed together
MAINTENANCE_DELAY = 60       # seconds after joining before the first upkeep (the first sync is done by then)
MAINTENANCE_INTERVAL = 3600  # seconds between upkeeps
LEDGER_EXPIRY_DAYS = 180     # ledger rows of nodes not seen for this long are dropped
MAX_SUCCESSION_DAYS = 3650
CLOCK_SKEW = timedelta(minutes=10)  # how far ahead of ours another node's clock may be
MAX_BAD_DATA = 20            # data with bad signatures a peer may send per connection before it's cut off
FILE_LABELS = {"admins": "admin list", "network_settings": "network settings", "allowlist": "allowlist",
               "blocklist": "blocklist", "node_ledger": "node ledger"}
KEY = re.compile(r"[0-9a-f]{64}")
BAD_SIGNATURE = "the signature doesn't match"


def short(key: str) -> str:
    return key[:8]


def parse_topic(topic: str) -> tuple[str, str]:
    """'<name>:<64-hex founder key>' -> (name, founder key)"""
    name, _, founder = topic.strip().rpartition(":")
    if not name or not KEY.fullmatch(founder):
        raise ValueError("a topic looks like '<name>:<64 hex characters>'. Ask the network's creator for it.")
    return name, founder


def version_key(envelope: dict) -> tuple:
    """Which copy of a file is newer: higher version wins. Ties (two admins
    changing the same version at once) go to the later last_modified, then the
    higher key, so every node picks the same winner."""
    try:
        version = int(envelope.get("version") or 0)
    except (TypeError, ValueError):
        version = -1
    return version, str(envelope.get("last_modified") or ""), str(envelope.get("modified_by") or "")


def record_key(record: dict) -> tuple:
    """Which copy of a record is newer: same rule as version_key."""
    try:
        serial = int(record.get("serial") or 0)
    except (TypeError, ValueError):
        serial = -1
    return serial, str(record.get("last_modified") or ""), str(record.get("updated_by") or "")


class Network:
    """Roles are decided from data every node can check: the founder (whose key
    is part of the topic) is always admin, and admins.json is only accepted
    when signed by an admin. What a peer claims about itself is never trusted."""

    def __init__(self, api: SidecarAPI, identity: Identity, topic: str, saved_networks: Path,
                 modules: dict[str, Module], missing_module: Callable[[str], None] = lambda name: None):
        self.api = api
        self.identity = identity
        self.topic = topic
        self.me = api.public_key
        _, self.founder = parse_topic(topic)
        self.modules = modules
        self.missing_module = missing_module  # called with a module name we got data for but don't run
        self.online: set[str] = set()
        # peer -> the address its connection to US came from (this session). Our own
        # observation, unlike the ledger's last_ip, which other nodes can write.
        self.addresses: dict[str, str] = {}
        self.greeted: set[str] = set()  # peers whose hello we've had on their current connection
        self.authed: set[str] = set()   # peers that passed the password check on their current connection
        self.password: str | None = None  # typed by the user for this session, until it's been accepted
        self.new_network_password: str | None = None  # set by /create; becomes the network's password for good
        self._challenges: dict[str, str] = {}  # peer -> nonce we're waiting for an answer to
        self._failures: dict[str, int] = {}    # peer -> wrong answers this session
        self._answered: dict[str, str] = {}    # salt -> key we answered a challenge with
        self._told_wrong_password = False
        self.notify: Callable[[str], None] = print
        # Called with the dissolving admin's key once a dissolve arrives (set by the controller).
        self.on_dissolved: Callable[[str], Awaitable] | None = None
        self._lock = asyncio.Lock()
        self._active = False
        self._ledger_push: asyncio.TimerHandle | None = None
        self._maintenance: asyncio.Task | None = None
        self._bad: dict[str, int] = {}  # peer -> data with bad signatures on its current connection
        self._session_start = parse_time(now())
        self._seen_before_session: datetime | None = None  # when we were last around before this session

        folder = network_folder(saved_networks, topic)
        self.settings = NetworkSettings(folder / "network_settings.json")
        self.admins = Admins(folder / "admins.json")
        self.allowlist = AccessList(folder / "allowlist.json")
        self.blocklist = AccessList(folder / "blocklist.json")
        self.ledger = NodeLedger(folder / "node_ledger.json")
        self.local_block = AccessList(saved_networks / "this_node_blocklist.json")
        self.files: dict[str, SyncedFile] = {
            "admins": self.admins, "network_settings": self.settings, "allowlist": self.allowlist,
            "blocklist": self.blocklist, LEDGER: self.ledger,
        }
        # Module files live in the same folder; their sync key is "<module>.<file>".
        self.record_specs: dict[str, tuple[Module, RecordFile]] = {}
        for module in modules.values():
            for spec in module.files:
                file_key = f"{module.name}.{spec.name}"
                self.files[file_key] = RecordStore(folder / f"{spec.name}.json", spec.key, spec.fields)
                self.record_specs[file_key] = (module, spec)

        if not self.settings["Topic"]:
            self.settings.update(Topic=topic, Name=self.entry["network_name"], allowlist=0)
        for f in self.files.values():
            if not f.path.exists():
                f.write()  # every network folder holds the full set of files from the start

    # --- state ------------------------------------------------------------

    @property
    def entry(self) -> dict:
        return self.identity.network(self.topic)

    @property
    def alias(self) -> str:
        return self.entry["alias"]

    @property
    def name(self) -> str:
        return self.settings["Name"] or self.entry["network_name"]

    def admin_keys(self) -> set[str]:
        return set(self.admins.keys()) | {self.founder}

    def role_of(self, identity: str) -> str:
        return ADMIN if identity in self.admin_keys() else MEMBER

    def is_admin(self, identity: str | None = None) -> bool:
        return self.role_of(identity or self.me) == ADMIN

    def name_of(self, key: str) -> str:
        if key == self.me:
            return self.alias
        row = self.ledger.get(key) or self.admins.get(key) or {}
        return row.get("alias") or short(key)

    # --- password -------------------------------------------------------------

    @property
    def requires_password(self) -> bool:
        return auth.valid(self.settings["password"])

    def trusted(self, peer: str) -> bool:
        """May this peer get and send network data? Only once it has passed the
        password check, if the network has a password."""
        return not self.requires_password or peer in self.authed

    def trusted_peers(self) -> set[str]:
        return {p for p in self.online if self.trusted(p)}

    def _challenge(self, peer: str):
        if self._failures.get(peer, 0) >= auth.MAX_FAILURES:
            self.api.disconnect(peer)  # too many wrong answers this session
            return
        setting = self.settings["password"]
        nonce = self._challenges[peer] = auth.new_nonce()
        self.api.send(peer, {"type": "auth_challenge", "nonce": nonce, "salt": setting["salt"],
                             **{k: setting[k] for k in auth.SCRYPT}})

    def _answer_challenge(self, peer: str, data: dict):
        entry = self.entry
        try:
            setting = {"salt": str(data["salt"]), **{k: int(data[k]) for k in auth.SCRYPT}}
            if entry.get("password_salt") == setting["salt"] and entry.get("password_key"):
                key = entry["password_key"]
            elif self.password is not None:
                key = auth.derive_for(self.password, setting)
            else:
                key = ""
        except (KeyError, ValueError, TypeError):
            key = ""  # malformed challenge: answer nothing useful
        if key:
            self._answered[setting["salt"]] = key
        answer = auth.proof(key, str(data.get("nonce", "")), self.topic, self.me) if key else ""
        self.api.send(peer, {"type": "auth_response", "proof": answer})

    def _check_answer(self, peer: str, data: dict):
        nonce = self._challenges.pop(peer, None)
        if nonce is None or not self.requires_password:
            return
        if auth.check(self.settings["password"], nonce, self.topic, peer, str(data.get("proof", ""))):
            self.authed.add(peer)
            self.api.send(peer, {"type": "auth_ok", "salt": self.settings["password"]["salt"]})
            self._greet(peer)
        else:
            self._failures[peer] = self._failures.get(peer, 0) + 1
            self.api.send(peer, {"type": "auth_failed"})
            # Give the message a moment to arrive before closing the connection.
            asyncio.get_running_loop().call_later(1, self.api.disconnect, peer)

    def _password_accepted(self, data: dict):
        key = self._answered.get(str(data.get("salt", "")))
        entry = self.entry
        if key and entry.get("password_key") != key:
            self.identity.update_network(self.topic, password_salt=data["salt"], password_key=key)
            self.notify("* network password accepted")
        self.password = None

    def _password_refused(self):
        if self.entry.get("password_key"):
            self.identity.update_network(self.topic, password_salt="", password_key="")
        if not self._told_wrong_password:
            self._told_wrong_password = True
            have = "That password is wrong" if self.password else "This network needs a password"
            self.notify(f"! {have}, so the network's members won't share anything with this node. "
                        f"Enter it with /network -password")

    # --- module hooks -------------------------------------------------------

    async def _call(self, module: Module, hook: str, *args):
        """Run one module hook. A failing module is reported and skipped; it
        mustn't stop other modules or the core from handling the event."""
        try:
            return await getattr(module, hook)(*args)
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            self.notify(f"! module '{module.name}' failed in {hook}: {e}")

    async def _call_all(self, hook: str, *args):
        for module in self.modules.values():
            await self._call(module, hook, *args)

    # --- lifecycle --------------------------------------------------------

    async def start(self):
        self._active = True
        self._session_start = parse_time(now())
        self._seen_before_session = self.last_seen(self.me)
        self._expire()  # after a long time away, don't hand out what has lapsed meanwhile
        self.ledger.seen(self.me, alias=self.alias)
        self._ledger_changed()
        async with self._lock:
            if self.me == self.founder and self.settings.version == 0:
                if self.new_network_password:
                    # The password is fixed here, in the network's first signed settings.
                    setting = auth.new_password(self.new_network_password)
                    self.settings.update(password=setting)
                    self.identity.update_network(self.topic, password_salt=setting["salt"],
                                                 password_key=setting["hash"])
                    self.new_network_password = None
                await self._commit("network_settings")  # so the network's name reaches everyone signed
        self._sync_own_role()
        self.update_firewall()
        self.api.join(self.topic)
        await self._call_all("on_join", self)
        if self.api.public_ip:
            await self._call_all("on_public_ip", self.api.public_ip)
        self._maintenance = asyncio.create_task(self._maintenance_loop())
        if self.is_admin() and len(self.admin_keys()) == 1:
            self.notify("* you are this network's only admin. If this device's identity is lost, nobody can "
                        "manage the network until succession makes a member admin. Consider a second admin "
                        "(/admin -append) and a backup (/identity -export).")

    async def stop(self):
        """Say goodbye to every peer and leave the topic."""
        await self._call_all("on_leave", self)
        self._active = False
        if self._ledger_push:
            self._ledger_push.cancel()
            self._ledger_push = None
        if self._maintenance:
            self._maintenance.cancel()
            self._maintenance = None
        await self.api.goodbye(self.topic, {"type": "goodbye"})
        self.api.firewall([], [])  # off-network: accept nobody, or peers reconnect behind our back
        self.online.clear()
        self.greeted.clear()
        self.authed.clear()
        self._challenges.clear()
        self.ledger.seen(self.me)  # sent with the sync when we rejoin

    def set_alias(self, alias: str):
        self.identity.update_network(self.topic, alias=alias)
        self.ledger.upsert(self.me, alias=alias)
        self.api.broadcast(self._hello())
        self._ledger_changed()

    def update_firewall(self):
        """Allowlist mode: only allowlisted nodes and admins get in.
        Blocklist mode: everyone except blocklisted nodes gets in.
        this_node_blocklist.json applies in both modes."""
        deny = set(self.local_block.keys())
        if self.settings.allowlist_mode:
            allow = sorted(set(self.allowlist.keys()) | self.admin_keys())
        else:
            allow = None
            deny |= set(self.blocklist.keys()) - {self.founder}
        self.api.firewall(allow, sorted(deny))

    def _sync_own_role(self) -> bool:
        """Mirror our role into identity.json. Returns True if it changed."""
        admin = int(self.is_admin())
        if self.entry.get("admin") != admin:
            self.identity.update_network(self.topic, admin=admin)
            return True
        return False

    # --- events from the sidecar -----------------------------------------

    async def handle(self, evt: dict):
        name = evt.get("event")
        if name == "joined" and evt.get("topic") == self.topic:
            self.notify(f"* connected to '{self.name}' as {self.role_of(self.me)}. Waiting for peers...")
        elif name == "peer_connected":
            peer = evt["peer"]
            self.online.add(peer)
            self.addresses[peer] = str(evt.get("ip") or "").removeprefix("::ffff:")
            self.ledger.seen(peer, ip=evt.get("ip"))
            self.api.send(peer, self._hello())
        elif name == "peer_disconnected":
            peer = evt["peer"]
            was_member = peer in self.greeted
            self.greeted.discard(peer)
            self.authed.discard(peer)
            self._challenges.pop(peer, None)
            self._bad.pop(peer, None)
            if peer in self.online:
                self.online.discard(peer)
                self.ledger.seen(peer)
                self._ledger_changed()
                if was_member:
                    self.notify(f"* {self.name_of(peer)} disconnected")
        elif name == "message":
            await self._on_message(evt["peer"], evt["data"])
        elif name == "public_ip" and self._active:
            await self._call_all("on_public_ip", evt["ip"])
        elif name == "peer_limited":
            self.notify(f"! {self.name_of(evt['peer'])} was disconnected and is refused for "
                        f"{evt.get('minutes', '?')} minutes: it {evt.get('reason', 'broke a limit')}")
        elif name == "error":
            self.notify(f"! {evt['message']}")

    def _hello(self) -> dict:
        return {"type": "hello", "alias": self.alias, "topic": self.topic}

    async def _on_message(self, peer: str, data):
        kind = data.get("type") if isinstance(data, dict) else None
        if not isinstance(kind, str):
            return

        if kind == "hello":
            if data.get("topic") != self.topic:
                self.api.disconnect(peer)
                return
            alias = str(data.get("alias", ""))[:64]
            old_alias = self.name_of(peer)
            self.ledger.seen(peer, alias=alias)
            self._ledger_changed()  # new connection, IP or alias: let everyone know
            if peer in self.greeted:
                # A second hello on the same connection means the alias changed.
                if alias != old_alias:
                    self.notify(f"* {old_alias} is now known as {alias}")
                return
            if not self.trusted(peer):
                if peer not in self._challenges:
                    self._challenge(peer)  # greeted once it answers correctly
                return
            self._greet(peer)

        elif kind == "auth_challenge":
            self._answer_challenge(peer, data)
        elif kind == "auth_response":
            self._check_answer(peer, data)
        elif kind == "auth_ok":
            self._password_accepted(data)
        elif kind == "auth_failed":
            self._password_refused()

        elif kind == "goodbye":
            self.ledger.seen(peer)
            if peer in self.greeted:
                self.notify(f"* {self.name_of(peer)} left the network")

        elif not self.trusted(peer):
            return  # no data from a node that hasn't passed the password check

        elif kind == "sync":
            files = data.get("files")
            if isinstance(files, dict):
                await self.receive(peer, files)

        elif "." in kind:
            module_name, _, sub = kind.partition(".")
            module = self.modules.get(module_name)
            if module:
                await self._call(module, "on_message", peer, sub, {k: v for k, v in data.items() if k != "type"})
            else:
                self.missing_module(module_name)

    def _greet(self, peer: str):
        self.greeted.add(peer)
        self.notify(f"* {self.name_of(peer)} connected ({self.role_of(peer)})")
        self.sync(peer)  # both sides do this, so whoever is behind catches up

    # --- messages for modules -----------------------------------------------

    def send_module_message(self, peer: str, kind: str, data: dict):
        if peer not in self.trusted_peers():
            raise ValueError(f"{self.name_of(peer)} is not online")
        self.api.send(peer, {**data, "type": kind})

    def broadcast_module_message(self, kind: str, data: dict):
        peers = self.trusted_peers()
        if not peers:
            raise ValueError("nobody else is online")
        for p in peers:
            self.api.send(p, {**data, "type": kind})

    # --- sync -----------------------------------------------------------------

    def sync(self, peer: str | None = None) -> int:
        """Send every network file to one peer, or to everyone. Returns how many
        peers it went to. Replies (newer files, or requests to catch up) are
        handled by receive() as they arrive."""
        msg = {"type": "sync", "files": {name: f.envelope() for name, f in self.files.items()}}
        peers = [peer] if peer else sorted(self.trusted_peers())
        for p in peers:
            self.api.send(p, msg)
        return len(peers)

    def _push(self, files: dict[str, dict], to: str | None = None, exclude: str | None = None):
        """Send data to one peer, or to every peer that passed the password check."""
        msg = {"type": "sync", "files": files}
        for p in [to] if to else self.trusted_peers() - {exclude}:
            self.api.send(p, msg)

    def _signed_payload(self, name: str, envelope: dict) -> str:
        """Exactly what gets signed. Includes the topic and file name, so a
        signed file can't be replayed on another network or as another file."""
        return json.dumps({
            "topic": self.topic, "file": name,
            "version": envelope.get("version"), "last_modified": envelope.get("last_modified"),
            "modified_by": envelope.get("modified_by"), "data": envelope.get("data"),
        }, sort_keys=True, separators=(",", ":"))

    async def _commit(self, name: str, also: dict | None = None):
        """After changing a core file locally: bump its version, sign it, save it,
        push it (with `also`, other files to send in the same message).
        Call with self._lock held."""
        f = self.files[name]
        f.stamp(version=f.version + 1, last_modified=now(), modified_by=self.me, signature="")
        f.stamp(signature=await self.api.sign(self._signed_payload(name, f.envelope())))
        self._push({name: f.envelope(), **(also or {})})

    async def receive(self, peer: str, files: dict):
        """Compare a peer's files with ours: take newer ones, send back ours where they're behind."""
        updated: dict[str, tuple] = {}         # core file -> (data before, envelope)
        new_records: dict[str, list] = {}      # module file key -> records we took over
        behind: dict[str, dict] = {}           # files where our copy is newer than the peer's
        took_over = ""                         # who became admin through succession, if anyone
        async with self._lock:
            was_admin = self.is_admin()
            # The ledger first: whether a succession claim holds depends on who was seen when.
            if isinstance(files.get(LEDGER), dict):
                learned, sender_behind = self._merge_ledger(files[LEDGER], peer)
                if learned:
                    self._ledger_changed()  # pushes to everyone, the sender included
                elif sender_behind:
                    behind[LEDGER] = self.ledger.envelope()
            for name in SIGNED_FILES:
                theirs = files.get(name)
                if not isinstance(theirs, dict):
                    continue
                mine = self.files[name]
                ours = mine.envelope()
                if version_key(theirs) > version_key(ours):
                    problem = await self._check(name, theirs)
                    if problem:
                        self.notify(f"! ignored {FILE_LABELS[name]} from {self.name_of(peer)}: {problem}")
                        if problem == BAD_SIGNATURE and self._bad_data(peer):
                            return
                        continue
                    if name == "network_settings":
                        # When a newly joined node first learns the network has a password,
                        # the members it's already talking to stay trusted.
                        self.authed |= self.greeted
                    claim_base = self._claim_base(theirs) if name == "admins" else None
                    if name == "admins" and theirs.get("modified_by") not in self.admin_keys():
                        took_over = theirs["modified_by"]  # a succession claim (it passed _check)
                    mine.replace(theirs)
                    if took_over and name == "admins":
                        self._remember_claim(claim_base)
                    updated[name] = (ours["data"], theirs)
                elif version_key(theirs) < version_key(ours):
                    behind[name] = ours
            for file_key in self.record_specs:
                if not isinstance(files.get(file_key), dict):
                    continue
                learned, missing = await self._merge_records(file_key, files[file_key], peer)
                if learned:
                    new_records[file_key] = learned
                if missing:
                    behind[file_key] = {"data": missing, "partial": True}
                if self._bad.get(peer, 0) >= MAX_BAD_DATA:
                    return  # cut off: nothing it sent is passed on

            if updated or new_records:
                # Pass it on, so peers we're connected to and the sender isn't also get it.
                forward = {n: env for n, (_, env) in updated.items()}
                forward |= {n: {"data": records, "partial": True} for n, records in new_records.items()}
                self._push(forward, exclude=peer)
                self._after_change(set(updated))
            if behind:
                self._push(behind, to=peer)

        # Data for modules we don't run: tell the user (once), don't use or relay it.
        for file_key in files:
            module_name = file_key.partition(".")[0]
            if "." in file_key and module_name not in self.modules:
                self.missing_module(module_name)

        for name, (before, env) in updated.items():
            by = self.name_of(env.get("modified_by", ""))
            if name == "admins" and took_over:
                days = self.settings.succession_days
                who = "you" if took_over == self.me else by
                self.notify(f"* no admin had been around for {days} days, so {who} took over as admin (succession)")
                continue
            for line in self._describe_change(name, before, env.get("data")):
                self.notify(f"* {by}: {line}")
        if took_over and was_admin:
            # We're an admin who was away when it happened. Signing the list ourselves
            # makes it an ordinary admin change, which nodes that have seen us since
            # (and so would refuse the claim) accept too.
            async with self._lock:
                await self._commit("admins")
            self.notify(f"* you were away; your node confirmed {self.name_of(took_over)} as admin")
        for file_key, records in new_records.items():
            module, spec = self.record_specs[file_key]
            for r in records:
                try:
                    what = module.describe_record(spec.name, r)
                except Exception:
                    what = f"{spec.name} '{r.get(spec.key)}' updated"
                self.notify(f"* {self.name_of(r['updated_by'])}: {what}")
            await self._call(module, "on_records", spec.name, records, peer)
        if self.is_admin() != was_admin:
            self.notify(f"* you are now {'an admin' if self.is_admin() else 'a member'} of '{self.name}'")
        if "network_settings" in updated and self.settings["dissolved"] and self.on_dissolved:
            # Passed on to our other peers above; now leave and forget it. As a separate
            # task: leaving waits for sidecar events, which queue behind this handler.
            self._dissolving = asyncio.create_task(
                self.on_dissolved(updated["network_settings"][1].get("modified_by", "")))

    async def _check(self, name: str, env: dict) -> str | None:
        """Why a received core file can't be accepted, or None if it's fine."""
        signer = str(env.get("modified_by") or "")
        if not KEY.fullmatch(signer):
            return "it isn't signed"
        expected = dict if name == "network_settings" else list
        if not isinstance(env.get("data"), expected):
            return "it's malformed"
        if signer not in self.admin_keys():
            if name != "admins" or not self.settings.succession_days:
                return f"{self.name_of(signer)} isn't an admin"
            problem = self._claim_problem(env)
            if problem:
                return f"{self.name_of(signer)} isn't an admin, and can't take over as one: {problem}"
        if name == "network_settings" and env["data"].get("Topic") not in ("", self.topic):
            return "it belongs to another network"
        if name == "network_settings":
            password = env["data"].get("password") or ""
            if password and not auth.valid(password):
                return "its password setting is malformed"
            # The password is fixed when the network is created. Once we have the
            # network's settings, any version with a different password is refused.
            if self.settings.version >= 1 and password != (self.settings["password"] or ""):
                return "the network password can't be changed (dissolve the network and create a new one)"
            succession = env["data"].get("succession", 0)
            if type(succession) is not int or not 0 <= succession <= MAX_SUCCESSION_DAYS:
                return "its succession setting is malformed"
        if not await self.api.verify(self._signed_payload(name, env), str(env.get("signature") or ""), signer):
            return BAD_SIGNATURE
        return None

    def _bad_data(self, peer: str) -> bool:
        """Count data from `peer` with a bad signature. Checking signatures costs
        time, so a peer that keeps sending bad ones is cut off. Returns True if it was."""
        self._bad[peer] = self._bad.get(peer, 0) + 1
        if self._bad[peer] != MAX_BAD_DATA:
            return self._bad[peer] > MAX_BAD_DATA
        self.notify(f"! {self.name_of(peer)} sent {MAX_BAD_DATA} pieces of data with bad signatures; disconnected")
        self.api.disconnect(peer)
        return True

    # --- module record files --------------------------------------------------

    def _clean_record(self, file_key: str, row: dict) -> dict:
        """A record in canonical form: what's stored, sent and signed.
        "deleted" is only present when true."""
        module, spec = self.record_specs[file_key]
        key = str(row.get(spec.key) or "")
        rec = {
            spec.key: key.lower() if spec.lowercase_key else key,
            "serial": record_key(row)[0],
            "last_modified": str(row.get("last_modified") or ""),
            "updated_by": str(row.get("updated_by") or ""),
            "signature": str(row.get("signature") or ""),
        }
        if row.get("deleted"):
            rec["deleted"] = True
        else:
            rec.update(module.clean_record(spec.name, row))
        return rec

    def _record_payload(self, file_key: str, rec: dict) -> str:
        """Exactly what gets signed for one record. Includes the topic and file,
        so it can't be replayed on another network or as another kind of record."""
        body = {k: v for k, v in rec.items() if k != "signature"}
        return json.dumps({"topic": self.topic, "file": file_key, **body}, sort_keys=True, separators=(",", ":"))

    def _store_record(self, file_key: str, rec: dict):
        module, spec = self.record_specs[file_key]
        values = {f: "" for f in spec.fields} | rec | {"deleted": bool(rec.get("deleted"))}
        self.files[file_key].upsert(rec[spec.key], **values)

    async def _check_record(self, file_key: str, rec: dict) -> str | None:
        """Why a received record can't be accepted, or None if it's fine."""
        module, spec = self.record_specs[file_key]
        signer = rec["updated_by"]
        if not rec[spec.key]:
            return "it has no key"
        if not KEY.fullmatch(signer):
            return "it isn't signed"
        try:
            problem = module.validate_record(spec.name, rec, signer)
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            return f"module '{module.name}' failed to check it: {e}"
        if problem:
            return problem
        if not await self.api.verify(self._record_payload(file_key, rec), rec["signature"], signer):
            return BAD_SIGNATURE
        return None

    def _expired(self, file_key: str, rec: dict) -> bool:
        """Has this record gone longer without being re-signed than its module allows?"""
        module, spec = self.record_specs[file_key]
        try:
            days = module.expires(spec.name, rec)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return False
        signed = parse_time(rec.get("last_modified"))
        return bool(days) and signed is not None and signed < days_ago(days)

    async def _merge_records(self, file_key: str, env: dict, peer: str) -> tuple[list, list]:
        """Take every record that's newer than ours and valid. Returns
        (records we took over, our records the sender doesn't have or has older)."""
        module, spec = self.record_specs[file_key]
        store = self.files[file_key]
        rows = env.get("data")
        theirs: dict[str, tuple] = {}
        learned = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            try:
                rec = self._clean_record(file_key, row)
            except Exception as e:
                traceback.print_exc(file=sys.stderr)
                self.notify(f"! module '{module.name}' couldn't read a {spec.name} record: {e}")
                continue
            key = rec[spec.key]
            theirs[key] = max(theirs.get(key, (-1,)), record_key(rec))
            mine = store.get(key)
            if mine and self._expired(file_key, mine):
                mine = None  # lapsed: a fresh record replaces it, even one that starts its serial over
            if (mine and record_key(rec) <= record_key(mine)) or self._expired(file_key, rec):
                continue
            problem = await self._check_record(file_key, rec)
            if problem:
                self.notify(f"! ignored {spec.name} record '{key}' from {self.name_of(peer)}: {problem}")
                if problem == BAD_SIGNATURE and self._bad_data(peer):
                    return [], []
                continue
            self._store_record(file_key, rec)
            learned.append(rec)
        # A push with only some records isn't proof the sender lacks the rest;
        # only answer full syncs with what they're missing.
        if env.get("partial"):
            return learned, []
        missing = [self._clean_record(file_key, r) for r in store.all()
                   if r.get("signature") and record_key(r) > theirs.get(r[spec.key], (-1,))
                   and not self._expired(file_key, r)]
        return learned, missing

    async def write_record(self, file_key: str, key: str, **fields) -> dict:
        """Create or change one record of a module file: next serial, checked with
        the module's validate_record, signed, saved, pushed to everyone."""
        module, spec = self.record_specs[file_key]
        async with self._lock:
            store = self.files[file_key]
            key = key.lower() if spec.lowercase_key else key
            current = store.get(key)
            rec = self._clean_record(file_key, {
                spec.key: key, **fields,
                "serial": record_key(current)[0] + 1 if current else 1,
                "last_modified": now(), "updated_by": self.me,
            })
            problem = module.validate_record(spec.name, rec, self.me)
            if problem:
                raise PermissionError(problem)
            rec["signature"] = await self.api.sign(self._record_payload(file_key, rec))
            self._store_record(file_key, rec)
            self._push({file_key: {"data": [rec], "partial": True}})
            return rec

    # --- ledger -----------------------------------------------------------------

    def _merge_ledger(self, env: dict, sender: str) -> tuple[bool, bool]:
        """Ledger rows aren't signed: take what others have seen, but never let
        them change our own row, and keep whichever row was seen most recently.
        Returns (we learned something new, the sender is missing something we know).

        Rows about the sender don't count towards "missing": the sender never
        takes anyone else's row about itself, so sending it ours would bounce
        between the two nodes forever."""
        rows = env.get("data")
        theirs: dict[str, str] = {}      # identity -> the sender's last_con for it
        first_seen: dict[str, str] = {}  # identity -> the sender's first_con for it
        learned = False
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            key = str(row.get("identity") or "")
            if not KEY.fullmatch(key):
                continue
            last_con = str(row.get("last_con") or "")
            theirs[key] = last_con
            first_seen[key] = str(row.get("first_con") or "")
            mine = self.ledger.get(key)
            if key == self.me or self._ledger_expired(row):
                continue
            first = min(filter(None, [str(row.get("first_con") or ""), (mine or {}).get("first_con", "")]), default="")
            if mine and last_con <= str(mine.get("last_con") or ""):
                # Not newer, but it may know of an earlier first connection (e.g. the
                # node's own row about itself): every node should agree who's been around longest.
                if first and first != mine.get("first_con"):
                    self.ledger.upsert(key, first_con=first)
                    learned = True
                continue
            self.ledger.upsert(key, alias=str(row.get("alias") or "")[:64] or None, first_con=first,
                               last_con=last_con, last_ip=str(row.get("last_ip") or ""))
            learned = True
        sender_behind = any(r["identity"] != sender and
                            (r["identity"] not in theirs or str(r.get("last_con") or "") > theirs[r["identity"]]
                             or str(r.get("first_con") or "") < first_seen.get(r["identity"], ""))
                            for r in self.ledger.all())
        return learned, sender_behind

    @staticmethod
    def _ledger_expired(row: dict) -> bool:
        seen = parse_time(row.get("last_con"))
        return seen is not None and seen < days_ago(LEDGER_EXPIRY_DAYS)

    def _ledger_changed(self):
        """Push the ledger to everyone a moment later. Connections come and go
        in bursts, so changes within LEDGER_PUSH_DELAY go out together."""
        if self._ledger_push or not self._active:
            return
        self._ledger_push = asyncio.get_running_loop().call_later(LEDGER_PUSH_DELAY, self._push_ledger)

    def _push_ledger(self):
        self._ledger_push = None
        if self._active and self.online:
            self._push({LEDGER: self.ledger.envelope()})

    # --- upkeep -------------------------------------------------------------------

    async def _maintenance_loop(self):
        await asyncio.sleep(MAINTENANCE_DELAY)
        while self._active:
            try:
                await self.maintain()
            except Exception as e:  # upkeep failing once mustn't stop it for good
                traceback.print_exc(file=sys.stderr)
                self.notify(f"! upkeep failed: {e}")
            await asyncio.sleep(MAINTENANCE_INTERVAL)

    async def maintain(self):
        """Hourly upkeep: note who's still here, drop what has expired, let
        modules re-sign what they keep alive, and check succession."""
        for key in {self.me} | self.trusted_peers():
            self.ledger.seen(key)  # a connection that stays up for weeks still counts as being around
        self._ledger_changed()
        await self._call_all("maintain")  # first, so what's being kept alive is re-signed before expiry
        self._expire()
        if not await self.check_succession() and self._claiming():
            self.sync()  # members who refused our claim (e.g. their ledger was behind) get another look

    def _claiming(self) -> bool:
        """Is the current admin list our own succession claim?"""
        claim = self.entry.get("succession_claim") or {}
        return self.admins.meta.get("modified_by") == self.me and claim.get("version") == self.admins.version

    def _expire(self):
        """Drop ledger rows and module records that have expired (see _expired)."""
        for row in self.ledger.all():
            if row["identity"] != self.me and self._ledger_expired(row):
                self.ledger.remove(row["identity"])
        for file_key, (module, spec) in self.record_specs.items():
            store = self.files[file_key]
            for rec in store.all():
                if self._expired(file_key, rec):
                    store.remove(rec[spec.key])

    # --- succession: when every admin has been gone for a long time -------------
    #
    # Nobody can sign for an admin who's gone, so a member signs an admin list
    # that adds itself (a "claim"). Every node accepts that only if, by its own
    # records: no admin was around in the succession period before the claim,
    # and the claimant was around and has been a member for that long. The
    # longest-standing member makes the claim, so normally only one does; if
    # two do, the usual version rule picks one everywhere.
    #
    # How long someone has been a member comes from the signed allowlist in
    # allowlist mode. In blocklist mode it comes from the node ledger, which
    # isn't signed: anyone who has the password could fake it. Networks that
    # don't want that can turn succession off (/network -succession 0).

    def last_seen(self, key: str) -> datetime | None:
        """When `key` was last known to be around: online (node ledger), or signing a core file."""
        stamps = [(self.ledger.get(key) or {}).get("last_con")]
        stamps += [self.files[n].meta.get("last_modified") for n in SIGNED_FILES
                   if self.files[n].meta.get("modified_by") == key]
        return max(filter(None, map(parse_time, stamps)), default=None)

    def member_since(self, key: str) -> datetime | None:
        """When an admin allowlisted `key` (signed, so trustworthy), or else when it was first seen."""
        added = (self.allowlist.get(key) or {}).get("added")
        return parse_time(added) or parse_time((self.ledger.get(key) or {}).get("first_con"))

    def _admins_present(self, at: datetime, days: int, admins: set[str]) -> str | None:
        """Which admin was around in the `days` before `at`, if any (as a reason), else None."""
        cutoff = at - timedelta(days=days)
        for admin in sorted(admins):
            if admin == self.me:  # we know our own absence best
                seen = self._seen_before_session if at < self._session_start else at
            else:
                seen = self.last_seen(admin)
            if seen and seen > cutoff:
                return f"{self.name_of(admin)} (an admin) was around less than {days} days before"
        return None

    def _successor_problem(self, key: str, at: datetime, days: int) -> str | None:
        """Why `key` can't take over as admin at `at`, or None if it can."""
        name = self.name_of(key)
        if self.is_admin(key):
            return f"{name} is already an admin"
        if key in self.blocklist:
            return f"{name} is blocked"
        if self.settings.allowlist_mode and key not in self.allowlist:
            return f"{name} isn't on the allowlist"
        cutoff = at - timedelta(days=days)
        since = self.member_since(key)
        if not since or since > cutoff:
            return f"{name} hasn't been a member for {days} days"
        seen = parse_time((self.ledger.get(key) or {}).get("last_con"))
        if key != self.me and (not seen or seen < cutoff):
            return f"{name} hasn't been around lately"
        return None

    def successor(self, at: datetime | None = None) -> str | None:
        """Who should take over: the longest-standing member that may."""
        at, days = at or parse_time(now()), self.settings.succession_days
        able = [r["identity"] for r in self.ledger.all() if not self._successor_problem(r["identity"], at, days)]
        return min(able, key=lambda k: (self.member_since(k), k), default=None)

    async def check_succession(self) -> bool:
        """Take over as admin if no admin has been around for the succession
        period and this node is the one that should. Returns True if it did."""
        days = self.settings.succession_days
        if not days or not self._active or self.is_admin() or self.settings["dissolved"]:
            return False
        at = parse_time(now())
        if self._admins_present(at, days, self.admin_keys()) or self.successor(at) != self.me:
            return False
        async with self._lock:
            base = sorted(self.admins.keys())
            self.admins.upsert(self.me, alias=self.alias)
            self.ledger.seen(self.me)
            # With the ledger: receivers judge the claim by who was around when,
            # so they get our view of that in the same message.
            await self._commit("admins", also={LEDGER: self.ledger.envelope()})
            self._remember_claim(base)
            self._after_change({"admins"})
        self.notify(f"* no admin has been around for {days} days: you took over as admin of '{self.name}' "
                    f"(succession). The other members accept this once they've checked it.")
        return True

    def _remember_claim(self, base: list[str]):
        """Which admin list the current (claimed) one built on: needed to judge a
        competing claim of the same version."""
        self.identity.update_network(self.topic, succession_claim={"version": self.admins.version, "base": base})

    def _claim_base(self, env: dict) -> list[str] | None:
        """The admin list a claim must build on: our current one, or, if ours is
        itself a claim of the same version, the one that built on."""
        version = version_key(env)[0]
        if version == self.admins.version + 1:
            return sorted(self.admins.keys())
        claim = self.entry.get("succession_claim") or {}
        if version == self.admins.version and claim.get("version") == version:
            return sorted(claim.get("base") or [])
        return None

    def _claim_problem(self, env: dict) -> str | None:
        """Why a claim (an admin list signed by a non-admin) can't be accepted, or None."""
        signer, days = env["modified_by"], self.settings.succession_days
        at = parse_time(env.get("last_modified"))
        if not at or at > parse_time(now()) + CLOCK_SKEW:
            return "its time is wrong"
        base = self._claim_base(env)
        listed = {r.get("identity") for r in env["data"] if isinstance(r, dict)}
        if base is None or listed != set(base) | {signer}:
            return "it isn't the current admin list with only its signer added"
        return self._admins_present(at, days, set(base) | {self.founder}) or self._successor_problem(signer, at, days)

    # --- after any change -------------------------------------------------------

    def _after_change(self, names: set[str]):
        """Side effects of new core data, whether we changed it or received it."""
        if "network_settings" in names:
            self.identity.update_network(self.topic, network_name=self.name)
        if names & {"admins", "network_settings", "allowlist", "blocklist"}:
            self.update_firewall()
        self._sync_own_role()

    def _describe_change(self, name: str, before, after) -> list[str]:
        """Human-readable summary of what a received core file changed."""
        label = FILE_LABELS[name]
        if name == "network_settings":
            before, after = before or {}, after or {}
            lines = []
            if before.get("Name") != after.get("Name"):
                lines.append(f"network renamed to '{after.get('Name')}'")
            if int(before.get("allowlist") or 0) != int(after.get("allowlist") or 0):
                lines.append(f"network mode set to {'1 (allowlist)' if int(after.get('allowlist') or 0) else '0 (blocklist)'}")
            if after.get("dissolved") and not before.get("dissolved"):
                lines.append("the network has been dissolved")
            if "succession" in after and before.get("succession") != after["succession"]:
                days = after["succession"]
                lines.append(f"succession set to {days} days" if days else "succession turned off")
            return lines or [f"{label} updated"]
        old = {r.get("identity") for r in before or [] if isinstance(r, dict)}
        new = {r.get("identity") for r in after or [] if isinstance(r, dict)}
        added = {"admins": "admin_add", "allowlist": "allow_add", "blocklist": "block_add"}[name]
        removed = {"admins": "admin_remove", "allowlist": "allow_remove", "blocklist": "block_remove"}[name]
        lines = [self.describe({"action": added, "identity": k}) for k in new - old]
        lines += [self.describe({"action": removed, "identity": k}) for k in old - new]
        return lines or [f"{label} updated"]

    # --- admin changes to core files --------------------------------------------

    async def admin(self, action: str, **fields):
        """Change a core setting or list (admins only), then sign and push it."""
        if not self.is_admin():
            raise PermissionError("only admins can change the network")
        target = fields.get("identity")
        if target == self.founder and action in ("block_add", "admin_remove", "allow_remove"):
            raise ValueError("the founder can't be blocked or demoted")
        alias = fields.get("alias")

        async with self._lock:
            if action == "allow_add":
                self.allowlist.upsert(target, alias=alias, added=now())
                name = "allowlist"
            elif action == "allow_remove":
                self.allowlist.remove(target)
                name = "allowlist"
            elif action == "block_add":
                self.blocklist.upsert(target, alias=alias, added=now())
                name = "blocklist"
            elif action == "block_remove":
                self.blocklist.remove(target)
                name = "blocklist"
            elif action == "admin_add":
                self.admins.upsert(target, alias=alias)
                name = "admins"
            elif action == "admin_remove":
                self.admins.remove(target)
                name = "admins"
            elif action == "set_name":
                self.settings.update(Name=str(fields["name"]).strip()[:64])
                name = "network_settings"
            elif action == "set_mode":
                self.settings.update(allowlist=1 if int(fields["allowlist"]) else 0)
                name = "network_settings"
            elif action == "dissolve":
                self.settings.update(dissolved=True)
                name = "network_settings"
            elif action == "set_succession":
                days = int(fields["days"])
                if not 0 <= days <= MAX_SUCCESSION_DAYS:
                    raise ValueError(f"days must be 0 (off) to {MAX_SUCCESSION_DAYS}")
                self.settings.update(succession=days)
                name = "network_settings"
            else:
                raise ValueError(f"unknown admin action {action!r}")

            # Push before applying side effects, so a peer this change disconnects
            # (block, allowlist mode) still receives it and knows why.
            await self._commit(name)
            self._after_change({name})

    def describe(self, msg: dict) -> str:
        action = msg["action"]
        if msg["identity"] == self.me:
            return {"allow_add": "you were added to the allowlist",
                    "allow_remove": "you were removed from the allowlist",
                    "block_add": "you were blocked", "block_remove": "you were unblocked",
                    "admin_add": "you were made an admin",
                    "admin_remove": "you are no longer an admin"}[action]
        verb = {"allow_add": "added to the allowlist", "allow_remove": "removed from the allowlist",
                "block_add": "blocked", "block_remove": "unblocked",
                "admin_add": "made an admin", "admin_remove": "is no longer an admin"}[action]
        return f"{self.name_of(msg['identity'])} {verb}"

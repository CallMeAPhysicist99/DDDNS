"""JSON-file storage.

data/                               (or the folder given with --data)
  config.json                       which modules are enabled (never synced)
  identity.json                     seed + every network this node has joined (never synced)
  dddns.log                         what happened (rotated: dddns.log.1, .2)
  history.txt                       typed commands, for Up/Down in the terminal
  saved_networks/
    this_node_blocklist.json        nodes this node never talks to, on any network (never synced)
    <network folder>/               everything about one network, core and modules alike
      network_settings.json         core: Topic, Name, allowlist (0 = blocklist mode, 1 = allowlist mode)
      admins.json                   core: who may change the network (the creator always may)
      allowlist.json / blocklist.json
      node_ledger.json              core: every node seen, with alias and last IP
      <module files>                e.g. dns_map.json, dns_delegations.json

Synced files share one envelope:
    {
        "last_modified": "<UTC time>",
        "version": <int, +1 on every change>,
        "modified_by": "<key of the admin who made the change>",
        "signature": "<that admin's signature over the file>",
        "data": <the actual list or settings>
    }
Files merged row by row (module record files and the ledger, see MergedStore)
only fill in last_modified: each record carries its own serial, signer and
signature, and ledger rows aren't signed.
Template rows whose key field is empty are ignored on load and dropped on save.
"""

import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Added to the real time. Only tests change it, to act out weeks passing.
CLOCK_OFFSET = timedelta(0)


def now() -> str:
    return (datetime.now(timezone.utc) + CLOCK_OFFSET).isoformat(timespec="seconds")


def parse_time(stamp) -> datetime | None:
    """A timestamp written by now() (or any ISO time) -> datetime in UTC; None if it isn't one."""
    try:
        t = datetime.fromisoformat(str(stamp))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def days_ago(days: float) -> datetime:
    return parse_time(now()) - timedelta(days=days)


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=4), encoding="utf-8")
    tmp.replace(path)  # atomic: never leaves a half-written file


def read_json(path: Path, default):
    if not path.exists():
        return default
    text = path.read_text(encoding="utf-8").strip()
    return json.loads(text) if text else default


# --- synced network files ------------------------------------------------------

class SyncedFile:
    """A network file inside the sync envelope. Subclasses decide what "data" holds."""

    META = ("last_modified", "version", "modified_by", "signature")

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.meta = {"last_modified": "", "version": 0, "modified_by": "", "signature": ""}
        raw = read_json(self.path, None)
        if isinstance(raw, dict) and "data" in raw:
            self.meta.update({k: raw[k] for k in self.META if k in raw})
            self._load_data(raw["data"])
        else:
            self._load_data(raw)  # pre-envelope file, or no file yet

    def _load_data(self, data):
        raise NotImplementedError

    def _dump_data(self):
        raise NotImplementedError

    @property
    def version(self) -> int:
        try:
            return int(self.meta.get("version") or 0)
        except (TypeError, ValueError):
            return 0

    def envelope(self) -> dict:
        return {**self.meta, "data": self._dump_data()}

    def write(self):
        write_json(self.path, self.envelope())

    def stamp(self, **meta):
        """Set version/last_modified/modified_by/signature after a change, and save."""
        self.meta.update({k: v for k, v in meta.items() if k in self.META})
        self.write()

    def replace(self, envelope: dict):
        """Take over a newer copy of this file received from the network."""
        self.meta = {k: envelope.get(k, "") for k in self.META}
        self._load_data(envelope.get("data"))
        self.write()


class JsonStore(SyncedFile):
    """data is a list of rows, keyed by one field ("identity", "hostname", ...)."""
    key = "identity"
    fields: tuple[str, ...] = ()

    def _load_data(self, data):
        rows = data if isinstance(data, list) else []
        self._rows: dict[str, dict] = {
            str(r[self.key]): {f: r.get(f, "") for f in self.fields} | {self.key: str(r[self.key])}
            for r in rows if isinstance(r, dict) and r.get(self.key)
        }

    def _dump_data(self):
        return list(self._rows.values())

    def get(self, key: str) -> dict | None:
        return self._rows.get(key)

    def all(self) -> list[dict]:
        return list(self._rows.values())

    def keys(self) -> list[str]:
        return list(self._rows)

    def upsert(self, key: str, **values) -> dict:
        """Create or update a row, filling missing fields with "" and saving."""
        row = self._rows.get(key) or {f: "" for f in self.fields}
        row[self.key] = key
        row.update({k: v for k, v in values.items() if v is not None and k in self.fields})
        self._rows[key] = row
        self.write()
        return row

    def remove(self, key: str) -> bool:
        existed = self._rows.pop(key, None) is not None
        if existed:
            self.write()
        return existed

    def __contains__(self, key: str) -> bool:
        return key in self._rows


class MergedStore(JsonStore):
    """A file merged row by row instead of signed as a whole (module record
    files, the ledger). Its envelope only tracks last_modified; version,
    modified_by and signature stay empty because each row carries its own."""

    def upsert(self, key: str, **values) -> dict:
        self.meta["last_modified"] = now()
        return super().upsert(key, **values)


class RecordStore(MergedStore):
    """A file of individually signed records (see core.module.RecordFile).
    A removed record stays as a signed record with "deleted": true, so it
    can't come back from a node that still has the old one."""

    RECORD_FIELDS = ("serial", "last_modified", "updated_by", "signature", "deleted")

    def __init__(self, path: str | Path, key: str, fields: tuple[str, ...]):
        self.key = key
        self.fields = (key, *fields, *self.RECORD_FIELDS)
        super().__init__(path)

    def active(self) -> list[dict]:
        return [r for r in self.all() if not r.get("deleted")]

    def lookup(self, key: str) -> dict | None:
        row = self.get(key)
        return row if row and not row.get("deleted") else None


class NodeLedger(MergedStore):
    """Every node seen on a network: identity, alias, when and at which IP.
    Roles aren't stored here; they come from admins.json."""
    fields = ("identity", "alias", "first_con", "last_con", "last_ip")

    def seen(self, identity: str, ip: str | None = None, **values) -> dict:
        existing = self.get(identity)
        stamp = now()
        return self.upsert(
            identity,
            first_con=existing["first_con"] if existing and existing.get("first_con") else stamp,
            last_con=stamp,
            last_ip=ip,
            **values,
        )


class Admins(JsonStore):
    """admins.json. The network's creator is an admin whether listed or not."""
    fields = ("identity", "alias")


class AccessList(JsonStore):
    """allowlist.json / blocklist.json / this_node_blocklist.json: who, and when they were added."""
    fields = ("identity", "alias", "added")


class NetworkSettings(SyncedFile):
    """network_settings.json. Your own alias lives in identity.json, not here,
    because this file is shared with the whole network.

    "password" is "" (no password) or {"salt", "hash", "n", "r", "p"}: a salted
    scrypt hash, never the password itself (see core.auth).
    "dissolved" is true once an admin has dissolved the network.
    "succession" is how many days without any admin online before a member
    takes over as admin (0 = never); see Network.check_succession.

    Optional settings are only written once they've been set, so settings
    signed before a setting existed still verify exactly as they were signed."""

    DEFAULTS = {"Topic": "", "Name": "", "allowlist": 0, "password": "", "dissolved": False, "succession": 30}
    ALWAYS = ("Topic", "Name", "allowlist")

    def _load_data(self, data):
        data = data if isinstance(data, dict) else {}
        self.data = {k: self.DEFAULTS[k] for k in self.ALWAYS}
        self.data.update({k: data[k] for k in self.DEFAULTS if k in data})

    def _dump_data(self):
        return dict(self.data)

    def __getitem__(self, key):
        return self.data.get(key, self.DEFAULTS[key])

    def update(self, **values):
        self.data.update(values)
        self.write()

    @property
    def allowlist_mode(self) -> bool:
        try:
            return int(self.data.get("allowlist") or 0) == 1
        except (TypeError, ValueError):
            return False

    @property
    def succession_days(self) -> int:
        try:
            return max(0, int(self["succession"]))
        except (TypeError, ValueError):
            return 0


# --- local files -----------------------------------------------------------------

class Identity:
    """identity.json: this node's seed plus every network it has joined.

    The seed gives this node ONE public key on every network. That's what lets
    this_node_blocklist.json work across networks, but it also means networks
    can tell they share a member.

    Each network's "admin" flag mirrors this node's role there, so the start
    menu can show it without opening the network. It's written by the core
    whenever the role changes; the role itself is decided by the network's
    admins.json, so editing the flag by hand changes nothing.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._load(read_json(self.path, {}))
        if not self.valid(self.as_dict()):
            self.seed = secrets.token_hex(32)
            self.save()

    def _load(self, data: dict):
        self.seed = data.get("seed") or ""
        self.networks = [n for n in data.get("networks", []) if isinstance(n, dict) and n.get("topic")]
        self.dissolved: list[str] = [t for t in data.get("dissolved", []) if isinstance(t, str)]

    @staticmethod
    def valid(data) -> bool:
        return isinstance(data, dict) and bool(re.fullmatch(r"[0-9a-f]{64}", str(data.get("seed") or "")))

    def as_dict(self) -> dict:
        data = {"seed": self.seed, "networks": self.networks}
        if self.dissolved:
            data["dissolved"] = self.dissolved  # topics of networks dissolved by their admins
        return data

    def save(self):
        write_json(self.path, self.as_dict())

    def replace(self, data: dict):
        """Become another identity (restoring a backup). The node must restart
        afterwards: the running sidecar still holds the old key."""
        self._load(data)
        self.save()

    def forget_dissolved(self, topic: str):
        """Drop a dissolved network from the saved list, and remember it was dissolved."""
        self.networks = [n for n in self.networks if n["topic"] != topic]
        if topic not in self.dissolved:
            self.dissolved.append(topic)
        self.save()

    def network(self, topic: str) -> dict | None:
        return next((n for n in self.networks if n["topic"] == topic), None)

    def add_network(self, topic: str, name: str, alias: str, admin: bool) -> dict:
        entry = {"topic": topic, "network_name": name, "alias": alias, "admin": int(admin)}
        self.networks.append(entry)
        self.save()
        return entry

    def update_network(self, topic: str, **values):
        entry = self.network(topic)
        if entry is not None:
            entry.update(values)
            self.save()


class Config:
    """config.json: {"modules": ["dns", "ddns", "chat"]} - which modules this node runs."""

    def __init__(self, path: str | Path, default_modules: list[str]):
        self.path = Path(path)
        data = read_json(self.path, None)
        if not isinstance(data, dict) or not isinstance(data.get("modules"), list):
            data = {"modules": list(default_modules)}
            write_json(self.path, data)
        self.data = data

    @property
    def modules(self) -> list[str]:
        return [m for m in self.data["modules"] if isinstance(m, str)]

    def set_modules(self, names: list[str]):
        self.data["modules"] = names
        write_json(self.path, self.data)


def network_folder(saved_networks: Path, topic: str) -> Path:
    """Folder for a network's files: '<name>_<first 8 chars of founder key>'.
    Derived from the topic, so it never changes even if admins rename the network."""
    name, _, founder = topic.rpartition(":")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_") or "network"
    return saved_networks / f"{safe}_{founder[:8]}"

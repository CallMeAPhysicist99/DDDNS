"""data/ddns_users.json: logins that devices (cameras, routers) use to send IP
updates to this node's DDNS endpoint. Local to this node, never synced: the
device's password stays here, and this node signs the update itself.

[{"username": "...", "salt": "...", "password_hash": "...", "hostnames": ["cam1", ...]}]
"""

import hashlib
import hmac
import secrets
from pathlib import Path

from core.storage import read_json, write_json


class DdnsUsers:
    ITERATIONS = 100_000

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._rows = {r["username"]: r for r in read_json(self.path, [])
                      if isinstance(r, dict) and r.get("username")}

    def _hash(self, password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), self.ITERATIONS).hex()

    def add(self, username: str, password: str, hostnames: list[str]):
        salt = secrets.token_hex(16)
        self._rows[username] = {"username": username, "salt": salt, "password_hash": self._hash(password, salt),
                                "hostnames": sorted({h.lower() for h in hostnames})}
        write_json(self.path, list(self._rows.values()))

    def remove(self, username: str) -> bool:
        if self._rows.pop(username, None) is None:
            return False
        write_json(self.path, list(self._rows.values()))
        return True

    def check(self, username: str, password: str) -> dict | None:
        """The login's row if the password is right, else None."""
        row = self._rows.get(username)
        if not row:
            self._hash(password, "00" * 16)  # same work either way, so timing doesn't reveal usernames
            return None
        return row if hmac.compare_digest(self._hash(password, row["salt"]), row["password_hash"]) else None

    def all(self) -> list[dict]:
        return list(self._rows.values())

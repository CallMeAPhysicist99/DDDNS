"""Network passwords, checked by the members themselves.

A password is chosen when the network is created and can't be changed: it's
part of the network's first signed settings, and members refuse any later
settings with a different one. To change it, dissolve the network and create
a new one (under a different name).

network_settings.json holds {"salt", "hash", "n", "r", "p"}: hash = scrypt(password,
salt). The password itself is never stored or sent.

When a node connects, each member that knows the network has a password sends
it a challenge (a random nonce plus the salt). The node answers with
    HMAC(scrypt(password, salt), nonce | topic | its own key)
which the member checks against the stored hash. The answer is bound to that
nonce and that node, so a captured answer can't be replayed. Until a node has
passed, members send it no data at all, not even the settings with the hash.

A node that joined successfully keeps the derived key (not the password) in
identity.json, so it can answer later challenges without asking again.
"""

import hashlib
import hmac
import secrets

SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}  # ~16 MB and a fraction of a second per derivation
MAX_FAILURES = 5  # wrong answers from one node before it's ignored for the session


def derive(password: str, salt: str, n: int, r: int, p: int) -> str:
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=n, r=r, p=p,
                          maxmem=64 * 1024 * 1024, dklen=32).hex()


def new_password(password: str) -> dict:
    """What goes into network_settings.json for a new password."""
    salt = secrets.token_hex(16)
    return {"salt": salt, "hash": derive(password, salt, **SCRYPT), **SCRYPT}


def valid(setting) -> bool:
    return (isinstance(setting, dict) and isinstance(setting.get("salt"), str) and isinstance(setting.get("hash"), str)
            and all(isinstance(setting.get(k), int) for k in SCRYPT))


def derive_for(password: str, setting: dict) -> str:
    return derive(password, setting["salt"], setting["n"], setting["r"], setting["p"])


def proof(key: str, nonce: str, topic: str, node: str) -> str:
    return hmac.new(bytes.fromhex(key), f"{nonce}|{topic}|{node}".encode(), hashlib.sha256).hexdigest()


def check(setting: dict, nonce: str, topic: str, node: str, answer: str) -> bool:
    return bool(answer) and hmac.compare_digest(proof(setting["hash"], nonce, topic, node), answer)


def new_nonce() -> str:
    return secrets.token_hex(16)

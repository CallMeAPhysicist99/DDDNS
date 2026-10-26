"""Backups of identity.json, encrypted with a passphrase.

identity.json holds this node's seed: its private key, the same on every
network. Whoever has it IS this node (an admin, if this node is one), so a
backup is only written encrypted:

  * the passphrase is stretched with scrypt (salted), giving two keys
  * the data is XORed with a SHAKE-256 keystream from the first key and a
    random nonce
  * an HMAC-SHA256 with the second key covers everything, so a wrong
    passphrase or a damaged file is detected before anything is used

Only the standard library is needed.
"""

import base64
import hashlib
import hmac
import json
import secrets

FORMAT = "dddns-identity-backup-1"
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
MIN_PASSPHRASE = 8


def _keys(passphrase: str, salt: bytes, n: int, r: int, p: int) -> tuple[bytes, bytes]:
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=n, r=r, p=p, dklen=64, maxmem=2 ** 26)
    return key[:32], key[32:]


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    return hashlib.shake_256(key + nonce).digest(length)


def _mac(key: bytes, sealed: dict) -> str:
    body = json.dumps({k: v for k, v in sealed.items() if k != "mac"}, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def seal(data: dict, passphrase: str) -> dict:
    """data -> an encrypted backup (a JSON-able dict)."""
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    enc_key, mac_key = _keys(passphrase, salt, **SCRYPT)
    plain = json.dumps(data).encode()
    cipher = bytes(a ^ b for a, b in zip(plain, _keystream(enc_key, nonce, len(plain))))
    sealed = {"format": FORMAT, **SCRYPT, "salt": salt.hex(), "nonce": nonce.hex(),
              "data": base64.b64encode(cipher).decode()}
    sealed["mac"] = _mac(mac_key, sealed)
    return sealed


def unseal(sealed, passphrase: str) -> dict:
    """An encrypted backup -> the data. ValueError if the passphrase is wrong or the file isn't a backup."""
    if not isinstance(sealed, dict) or sealed.get("format") != FORMAT:
        raise ValueError("that file isn't a DDDNS identity backup")
    try:
        enc_key, mac_key = _keys(passphrase, bytes.fromhex(sealed["salt"]),
                                 **{k: int(sealed[k]) for k in SCRYPT})
        nonce, cipher = bytes.fromhex(sealed["nonce"]), base64.b64decode(sealed["data"])
    except (KeyError, ValueError, TypeError):
        raise ValueError("the backup file is damaged")
    if not hmac.compare_digest(_mac(mac_key, sealed), str(sealed.get("mac", ""))):
        raise ValueError("wrong passphrase, or the backup file is damaged")
    plain = bytes(a ^ b for a, b in zip(cipher, _keystream(enc_key, nonce, len(cipher))))
    return json.loads(plain)

"""What a module is, and how it plugs into the core.

The core is a decentralized network with nothing in it: identity, joining,
roles, allow/block lists, the ledger, signed sync and peer messages. Modules
give it a purpose. A module is a subclass of Module that can declare:

  commands     @command("dns", "assign", "<HOST> <ID>", admin=True, help="...")
               Methods returning their output (str, list of lines, or None).
               admin=True: the core refuses it for members (convenience only;
               the real rule is the module's validate_record, see below).

  files        files = [RecordFile("dns_map", key="hostname", fields=("ip",))]
               Stored in the network's folder next to the core files, signed,
               synced and relayed by the core. Every record a peer sends is
               checked by validate_record() before it's accepted: that's where
               "who may change what" is enforced.

  messages     self.send(peer, "dm", {...}) / self.broadcast("dm", {...}) arrive
               at the other side's on_message(peer, "dm", data). Message types
               are namespaced by module ("chat.dm") automatically.

  hooks        start/stop (program lifetime: servers etc.), on_join/on_leave
               (a network is opened/closed), on_public_ip, on_records, on_message,
               maintain (hourly), plus info hooks so core commands can show
               module details.

  expiry       expires() lets records lapse unless they're re-signed, e.g. a
               node's own hostname once that node has been gone for months.

A node that receives files or messages for a module it doesn't run doesn't use
or relay them (it can't verify them), but tells the user once which module the
network uses.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.controller import Controller
    from core.network import Network


class CommandError(ValueError):
    """A command can't run: the message is shown to the user as '! <message>'."""


@dataclass
class RecordFile:
    """A file of individually signed records, merged record by record (highest
    serial wins per key). The module's validate_record() decides who may write
    which record."""
    name: str                      # file name without .json, e.g. "dns_map"
    key: str                       # field that identifies a record, e.g. "hostname"
    fields: tuple[str, ...] = ()   # the module's own fields, e.g. ("ip",)
    lowercase_key: bool = False    # e.g. hostnames are case-insensitive


@dataclass
class Command:
    name: str
    flag: str | None
    args: str
    admin: bool
    needs_network: bool
    help: str
    owner: Any = None              # the Module (or Controller) whose method runs it
    method: str = ""

    @property
    def usage(self) -> str:
        return " ".join(p for p in (f"/{self.name}", f"-{self.flag}" if self.flag else "", self.args) if p)

    @property
    def label(self) -> str:
        return f"/{self.name}" + (f" -{self.flag}" if self.flag else "")


def command(name: str, flag: str | None = None, args: str = "", admin: bool = False,
            needs_network: bool = True, help: str = ""):
    """Mark a method as a CLI command. It receives the text after the command
    and returns its output (str, list of str, or None)."""
    def mark(fn):
        fn._command = dict(name=name, flag=flag, args=args, admin=admin, needs_network=needs_network, help=help)
        return fn
    return mark


def commands_of(obj) -> list[Command]:
    """obj's commands, in the order they're written in its class (that's the /help order)."""
    found = []
    for attr in dir(type(obj)):
        fn = getattr(type(obj), attr)
        spec = getattr(fn, "_command", None)
        if spec:
            found.append((fn.__code__.co_firstlineno, Command(**spec, owner=obj, method=attr)))
    return [cmd for _, cmd in sorted(found, key=lambda pair: pair[0])]


class Module:
    name: str = ""                 # e.g. "dns"; also the namespace for its files' sync keys and messages
    title: str = ""                # heading in /help
    requires: tuple[str, ...] = () # modules that must be enabled too, e.g. ddns requires ("dns",)
    files: list[RecordFile] = []

    def __init__(self, controller: "Controller"):
        self.controller = controller
        self.options: dict = {}    # set by main.py from command-line options

    # --- shortcuts -------------------------------------------------------------

    @property
    def net(self) -> "Network | None":
        return self.controller.net

    def notify(self, text: str):
        self.controller.notify(text)

    async def ask(self, prompt: str, secret: bool = False) -> str:
        """Ask the user something (secret: hide what's typed, e.g. passwords)."""
        return await self.controller.ask(prompt, secret)

    def send(self, peer: str, kind: str, data: dict):
        self.net.send_module_message(peer, f"{self.name}.{kind}", data)

    def broadcast(self, kind: str, data: dict):
        self.net.broadcast_module_message(f"{self.name}.{kind}", data)

    def store(self, file_name: str):
        """This module's RecordStore for `file_name` on the open network."""
        return self.net.files[f"{self.name}.{file_name}"]

    async def write_record(self, file_name: str, key: str, **fields) -> dict:
        """Create or change one record: checked with validate_record, signed, saved, pushed."""
        return await self.net.write_record(f"{self.name}.{file_name}", key, **fields)

    # --- hooks (override what you need) ---------------------------------------

    async def start(self):
        """Program start: start servers etc. Return a line to show at start-up, or None."""

    async def stop(self):
        """Program exit."""

    async def on_join(self, net: "Network"):
        """A network was opened (after its files are loaded)."""

    async def on_leave(self, net: "Network"):
        """The network is being closed."""

    async def on_public_ip(self, ip: str):
        """This node's public IP became known or changed."""

    async def on_records(self, file_name: str, records: list[dict], from_peer: str):
        """Records were taken over from the network (already validated and saved)."""

    async def on_message(self, peer: str, kind: str, data: dict):
        """A peer sent this module a message (kind without the module prefix)."""

    async def maintain(self):
        """Runs about once an hour while on a network (e.g. re-sign records so they don't expire)."""

    def expires(self, file_name: str, rec: dict) -> float | None:
        """After how many days without being re-signed this record expires, or
        None if it never does (the default). Expired records are dropped by
        every node and refused when they come back, so nobody needs to delete
        them; a record that should stay must be re-signed (see maintain)."""
        return None

    def clean_record(self, file_name: str, row: dict) -> dict:
        """The module's own fields of a record in canonical form (what's signed).
        Default: every declared field as a string."""
        spec = next(f for f in self.files if f.name == file_name)
        return {f: str(row.get(f) or "") for f in spec.fields}

    def validate_record(self, file_name: str, rec: dict, signer: str) -> str | None:
        """Why `signer` may not write this record, or None if it may.
        Runs for records from peers AND for our own writes. Default: admins only."""
        return None if self.net.is_admin(signer) else f"{self.net.name_of(signer)} isn't an admin"

    def describe_record(self, file_name: str, rec: dict) -> str:
        """One line for the notification when a record arrives."""
        spec = next(f for f in self.files if f.name == file_name)
        return f"{file_name} '{rec.get(spec.key)}' {'removed' if rec.get('deleted') else 'updated'}"

    def network_info(self) -> list[str]:
        """Extra lines for /network -info."""
        return []

    def user_info(self, key: str) -> list[str]:
        """Extra lines for /netuser -info (key is this node's)."""
        return []

    def peer_tags(self, key: str) -> str:
        """Short extra text after a node in /network -list."""
        return ""

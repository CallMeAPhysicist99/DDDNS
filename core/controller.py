"""The controller: owns the open network, loads modules, keeps the command
registry (core commands + every module's commands) and runs the console.

Commands return their output instead of printing it, so the same commands
could later be driven by something other than the console (headless, web).

Runs on the asyncio event loop. The console is core.terminal (prompt_toolkit),
or core.console_classic as a fallback.
"""

import importlib
import inspect
import json
import pkgutil
import shutil
import sys
import traceback
from pathlib import Path

import modules as modules_package
from core import backup
from core.headless import HeadlessConsole, log
from core.module import Command, CommandError, Module, command, commands_of
from core.network import ADMIN, CORE_FILES, FILE_LABELS, KEY, MAX_SUCCESSION_DAYS, MEMBER, Network, parse_topic, short
from core.sidecar_api import SidecarAPI
from core.storage import Config, Identity, MergedStore, network_folder, now, read_json, write_json
from core.terminal import make_console

DATA = Path(__file__).parent.parent / "data"
SAVED = DATA / "saved_networks"

CORE_HELP_GROUPS = [
    ("General", ["help", "show", "join", "create", "exit", "module", "quit"]),
    ("You", ["netuser", "identity"]),
    ("Network", ["network"]),
    ("Access", ["allowlist", "blocklist", "admin"]),
]

LIST_ACTIONS = {
    ("allowlist", "append"): "allow_add", ("allowlist", "remove"): "allow_remove",
    ("blocklist", "append"): "block_add", ("blocklist", "remove"): "block_remove",
    ("admin", "append"): "admin_add", ("admin", "remove"): "admin_remove",
}


def available_modules() -> dict[str, type[Module]]:
    """Every module in the modules/ folder, by name."""
    found = {}
    for info in pkgutil.iter_modules(modules_package.__path__):
        package = importlib.import_module(f"modules.{info.name}")
        cls = getattr(package, "MODULE", None)
        if cls:
            found[cls.name] = cls
    return found


class Controller:
    def __init__(self, identity: Identity, api: SidecarAPI, config: Config, options: dict | None = None,
                 saved_networks: Path = SAVED):
        self.identity = identity
        self.api = api
        self.config = config
        self.saved = saved_networks
        self.net: Network | None = None
        self.running = True
        self.exit_code = 0  # non-zero tells a service manager to restart us
        self.options = options or {}
        self.console = None  # created in run(), on the event loop (core.terminal.make_console)
        self._missing_reported: set[str] = set()

        self.available = available_modules()
        self.modules: dict[str, Module] = {}
        self.commands: list[Command] = commands_of(self)
        for name in self._load_order(config.modules):
            module = self.available[name](self)
            module.options = self.options
            problem = self._conflict(module)
            if problem:
                print(f"! module '{name}' skipped: {problem}")
                continue
            self.modules[name] = module
            self.commands += commands_of(module)
        api.on("*")(self._on_event)

    def _conflict(self, module: Module) -> str | None:
        """Why `module` can't be loaded next to what's already loaded, or None."""
        missing = [dep for dep in module.requires if dep not in self.modules]
        if missing:
            return f"it needs {', '.join(missing)}, which didn't load"
        taken = set(CORE_FILES) | {spec.name for m in self.modules.values() for spec in m.files}
        clashes = [spec.name for spec in module.files if spec.name in taken]
        if clashes:
            return f"its file{'s' if len(clashes) > 1 else ''} {', '.join(c + '.json' for c in clashes)} would overwrite another's"
        used = {(c.name, c.flag) for c in self.commands}
        clashes = [c.label for c in commands_of(module) if (c.name, c.flag) in used]
        if clashes:
            return f"command{'s' if len(clashes) > 1 else ''} {', '.join(clashes)} already exist{'s' if len(clashes) == 1 else ''}"
        return None

    def _load_order(self, wanted: list[str]) -> list[str]:
        """Enabled modules that exist, with whatever they require loaded first."""
        order: list[str] = []

        def add(name: str, chain: tuple = ()):
            if name in order or name in chain:
                return
            if name not in self.available:
                print(f"! module '{name}' is enabled in config.json but doesn't exist; skipped")
                return
            for dep in self.available[name].requires:
                if dep not in wanted:
                    print(f"! module '{name}' needs '{dep}', which isn't enabled; '{name}' skipped")
                    return
                add(dep, chain + (name,))
            order.append(name)

        for name in wanted:
            add(name)
        return order

    # --- output -------------------------------------------------------------

    async def _on_event(self, evt: dict):
        if evt.get("event") == "sidecar_died":
            self.notify(f"! the network process (sidecar) stopped unexpectedly (exit code {evt.get('code')}). "
                        f"This node is offline; restart the program to reconnect.")
            self.exit_code = 1
            self.stop()
            return
        net = self.net
        if net:
            await net.handle(evt)

    @property
    def prompt(self) -> str:
        if not self.net:
            return "> "
        n = self.net
        return f"{n.alias}@{n.name} [{n.role_of(n.me)}]> "

    def notify(self, text: str):
        """A message from the network, shown without disturbing what's being typed,
        and written to the log file."""
        log.info(text)
        if self.console:
            self.console.show(text)
        elif not log.handlers or not self.headless:
            print(text, flush=True)

    @property
    def headless(self) -> bool:
        return bool(self.options.get("headless"))

    def stop(self):
        """End the program as if /quit was typed (Ctrl+C, SIGTERM, a dead sidecar)."""
        self.running = False
        if self.console:
            self.console.stop()

    async def ask(self, prompt: str, secret: bool = False) -> str:
        """A question that needs an answer (asked again if left empty)."""
        while True:
            value = (await self.console.input(prompt, secret=secret)).strip()
            if value:
                return value

    def toolbar(self) -> str:
        """The terminal's status bar."""
        if not self.net:
            return "not on a network   ·   /show, /join, /create   ·   Tab completes, ↑ history"
        n = self.net
        parts = [n.name, n.role_of(n.me), f"{len(n.trusted_peers())} online"]
        dns = self.modules.get("dns")
        if dns and getattr(dns, "server", None) and dns.server.port:
            parts.append(f"DNS :{dns.server.port}")
        return "   ·   ".join(parts) + "   ·   /help"

    def complete(self, before: str) -> list[str]:
        """Tab completion: whole-line suggestions for the text before the cursor.
        Only commands this node may use right now are offered."""
        if not before.startswith("/"):
            return []
        usable = [c for c in self.commands
                  if (not c.needs_network or self.net) and (not c.admin or (self.net and self.net.is_admin()))]
        words = before.split(" ")
        if len(words) == 1:
            return sorted({f"/{c.name} " for c in usable if f"/{c.name}".startswith(before)})
        name = words[0][1:]
        options = [c for c in usable if c.name == name]
        if len(words) == 2 and any(c.flag for c in options):
            return [f"/{name} -{c.flag} " for c in options if c.flag and f"-{c.flag}".startswith(words[1])]
        # A member's name where the command takes an <ID>.
        flag = words[1][1:] if words[1].startswith("-") else None
        cmd = next((c for c in options if c.flag == flag), None) or next((c for c in options if c.flag is None), None)
        if cmd and "<ID>" in cmd.args and self.net:
            head, word = before.rsplit(" ", 1)
            names = {self.net.name_of(r["identity"]) for r in self.net.ledger.all() if r["identity"] != self.net.me}
            return [f"{head} {n} " for n in sorted(names) if n.lower().startswith(word.lower()) and " " not in n]
        return []

    def _missing_module(self, name: str):
        if name in self._missing_reported:
            return
        self._missing_reported.add(name)
        how = (f"enable it with /module -enable {name} and restart" if name in self.available
               else "this node doesn't have it installed")
        self.notify(f"! this network uses the '{name}' module, which this node doesn't run ({how}). "
                    f"Its data is ignored here.")

    # --- loop ---------------------------------------------------------------

    async def start_modules(self) -> list[str]:
        """Start every module's services. Returns their start-up messages."""
        lines = []
        for module in self.modules.values():
            try:
                line = await module.start()
            except Exception as e:  # one module failing to start mustn't stop the others
                traceback.print_exc(file=sys.stderr)
                line = f"! module '{module.name}' failed to start: {e}"
            if line:
                lines.append(line)
        return lines

    async def stop_modules(self):
        for module in reversed(list(self.modules.values())):
            try:
                await module.stop()
            except Exception:
                traceback.print_exc(file=sys.stderr)

    async def run(self):
        if not self.console:
            self.console = HeadlessConsole() if self.headless else make_console(
                self.saved.parent / "history.txt", self.complete, self.toolbar,
                classic=self.options.get("classic", False))
        try:
            if not self.headless:
                self.console.write(self.menu())
            which = self.options.get("network")
            if self.headless and not which:
                which = self._only_saved_network()
            if which:
                self.console.write(await self.execute_open(which))
            if self.headless and not self.net:
                self.exit_code = 2  # nothing to do: a configuration problem, restarting won't help
                return
            while self.running:
                try:
                    line = (await self.console.input(self.prompt, command=True)).strip()
                except EOFError:
                    break
                if not line:
                    continue
                output = await self.execute(line)
                if output:
                    self.console.write(output)
        finally:
            self.console.close()

    async def shutdown(self):
        if self.net:
            await self.leave()

    async def execute(self, line: str) -> str:
        """Run one command line. Returns its output (errors as '! ...')."""
        try:
            result = await self._dispatch(line)
        except (ValueError, PermissionError) as e:  # CommandError is a ValueError
            return f"! {e}"
        except Exception as e:  # a bug in a command mustn't take the program down
            traceback.print_exc(file=sys.stderr)
            return f"! that command failed: {e}"
        if result is None:
            return ""
        return result if isinstance(result, str) else "\n".join(result)

    async def _dispatch(self, line: str):
        if not self.net and line.isdigit():
            return await self.rejoin(int(line))
        if not line.startswith("/"):
            raise CommandError("commands start with '/'. Type /help.")

        word, _, rest = line[1:].partition(" ")
        word, rest = word.lower(), rest.strip()
        options = [c for c in self.commands if c.name == word]
        if not options:
            raise CommandError(f"unknown command /{word}. Type /help.")

        plain = next((c for c in options if c.flag is None), None)
        flag, _, flag_args = rest.partition(" ")
        flagged = next((c for c in options if c.flag and flag == f"-{c.flag}"), None)
        if flagged:
            command_, args = flagged, flag_args.strip()
        elif plain:
            command_, args = plain, rest
        else:
            raise CommandError(f"/{word} needs one of:\n" + "\n".join(f"    {c.usage}" for c in options))

        if command_.needs_network and not self.net:
            raise CommandError("join or create a network first")
        if command_.admin and not self.net.is_admin():
            raise PermissionError(f"{command_.label} is for admins only. You are a member of '{self.net.name}'.")
        if "<" in command_.args and not args:
            raise CommandError(f"usage: {command_.usage}")
        result = getattr(command_.owner, command_.method)(args)
        return await result if inspect.isawaitable(result) else result

    # --- networks -----------------------------------------------------------

    def menu(self) -> str:
        lines = ["", "=== DDDNS ==="]
        if self.identity.networks:
            lines.append("Your networks:")
            for i, n in enumerate(self.identity.networks, 1):
                role = ADMIN if n.get("admin") else MEMBER
                lines.append(f"  {i}) {n['network_name']:20} as {n['alias']:14} ({role})")
            lines.append("Type a number to rejoin, or use /join <Topic> or /create <Topic>.")
        else:
            lines.append("You haven't joined any networks yet. Use /join <Topic> or /create <Topic>.")
        lines.append("/help shows all commands.\n")
        return "\n".join(lines)

    async def enter(self, topic: str, password: str | None = None, new_network_password: str | None = None) -> list[str]:
        out = []
        if self.net:
            out += await self.leave()
        net = Network(self.api, self.identity, topic, self.saved, self.modules, self._missing_module)
        net.notify = self.notify
        net.password = password
        net.new_network_password = new_network_password
        net.on_dissolved = self._network_dissolved
        self.net = net
        await net.start()
        out.append(f"\nYou are in '{net.name}' as {net.alias} ({net.role_of(net.me)}). Type /help for commands.")
        return out

    async def leave(self) -> list[str]:
        net, self.net = self.net, None
        await net.stop()
        return ["  said goodbye and left the network"]

    def _forget(self, topic: str):
        """Remove a dissolved network from this node: the saved list and its folder."""
        self.identity.forget_dissolved(topic)
        shutil.rmtree(network_folder(self.saved, topic), ignore_errors=True)

    async def _network_dissolved(self, by_key: str):
        net = self.net
        if not net:
            return
        topic, name, by = net.topic, net.name, net.name_of(by_key)
        self.notify(f"* {by} dissolved the network '{name}'. Leaving it and deleting its data from this node...")
        await self.leave()
        self._forget(topic)
        if self.headless:
            self.notify(f"* '{name}' is gone from this node; nothing left to do, stopping.")
            self.exit_code = 2
            self.stop()
            return
        self.notify(f"* '{name}' is gone from this node.\n{self.menu()}")

    async def rejoin(self, number: int):
        if not 1 <= number <= len(self.identity.networks):
            raise CommandError(f"no network number {number}")
        return await self.enter(self.identity.networks[number - 1]["topic"])

    def saved_network(self, which: str) -> dict:
        """A saved network by its number in the menu, its topic, or its name."""
        nets = self.identity.networks
        which = which.strip()
        found = ([nets[int(which) - 1]] if which.isdigit() and 1 <= int(which) <= len(nets)
                 else [n for n in nets if n["topic"] == which]
                 or [n for n in nets if n["network_name"].lower() == which.lower()])
        if len(found) == 1:
            return found[0]
        if found:
            raise CommandError(f"you have {len(found)} networks called '{which}'; use its number or topic")
        saved = ", ".join(f"{i}) {n['network_name']}" for i, n in enumerate(nets, 1)) or "none"
        raise CommandError(f"no saved network '{which}' (saved: {saved}). Join a network once without "
                           f"--headless first; after that it can be opened by name.")

    def _only_saved_network(self) -> str | None:
        """Headless without --network: the one saved network, if there's exactly one."""
        if len(self.identity.networks) == 1:
            return self.identity.networks[0]["topic"]
        self.console.write("! headless mode needs --network <name> when there isn't exactly one saved network "
                           f"(saved: {', '.join(n['network_name'] for n in self.identity.networks) or 'none'})")
        return None

    async def execute_open(self, which: str) -> str:
        """Open a saved network (--network at start-up). Returns the output, errors as '! ...'."""
        try:
            return "\n".join(await self.enter(self.saved_network(which)["topic"]))
        except (ValueError, PermissionError) as e:
            return f"! {e}"

    # =========================================================================
    # Core commands
    # =========================================================================

    @command("help", needs_network=False, help="displays all commands")
    def cmd_help(self, arg):
        if self.net:
            role = "ADMIN" if self.net.is_admin() else "MEMBER"
            out = [f"\nYou are: {role} of '{self.net.name}'.  Commands marked A are admin only."]
        else:
            out = ["\nYou are not on a network.  Commands marked A are admin only."]
        groups = [(title, [c for c in self.commands if c.name in names and c.owner is self])
                  for title, names in CORE_HELP_GROUPS]
        groups += [(m.title or m.name, [c for c in self.commands if c.owner is m]) for m in self.modules.values()]
        width = max(len(c.usage) for c in self.commands)
        for title, cmds in groups:
            if cmds:
                out.append(f"\n{title}")
                out += [f"  {'A' if c.admin else ' '} {c.usage:{width}}  {c.help}" for c in cmds]
        out.append("")
        return out

    @command("join", args="<Topic>", needs_network=False, help="joins a network by its topic")
    async def cmd_join(self, arg):
        topic = arg.strip()
        name, _ = parse_topic(topic)
        if topic in self.identity.dissolved:
            raise CommandError("that network was dissolved by its admins")
        if self.net and self.net.topic == topic:
            raise CommandError("you're already on this network")
        out, password = [], None
        if self.identity.network(topic):
            out.append("You've joined this network before; using your saved alias.")
        else:
            alias = await self.ask("Your alias on this network: ")
            password = (await self.console.input("Network password (press Enter if it has none): ",
                                                 secret=True)).strip() or None
            self.identity.add_network(topic, name, alias[:64], admin=False)
        return out + await self.enter(topic, password)

    @command("create", args="<Topic>", needs_network=False, help="creates a new network; you become its admin")
    async def cmd_create(self, arg):
        name = arg.strip()
        if ":" in name:
            raise CommandError("the topic can't contain ':'")
        topic = f"{name}:{self.api.public_key}"
        if self.identity.network(topic):
            raise CommandError(f"you already created '{name}'. Use /join {topic} to go back to it.")
        if topic in self.identity.dissolved:
            raise CommandError(f"you dissolved a network called '{name}' before; pick another name")
        alias = await self.ask("Your alias on this network: ")
        password = (await self.console.input("Network password (press Enter for none; it can't be changed later): ",
                                             secret=True)).strip() or None
        self.identity.add_network(topic, name, alias[:64], admin=True)
        out = [f"\nNetwork created. Share this topic so others can join:\n  {topic}"]
        if password:
            out.append("  Members will need the password too. To change it later, dissolve the network "
                       "and create a new one with a different name.")
        return out + await self.enter(topic, new_network_password=password)

    @command("show", needs_network=False, help="lists your saved networks")
    def cmd_show(self, arg):
        if not self.identity.networks:
            return "  You haven't joined any networks yet. Use /join <Topic> or /create <Topic>."
        out = []
        for i, n in enumerate(self.identity.networks, 1):
            role = ADMIN if n.get("admin") else MEMBER
            here = "  <- you're here" if self.net and self.net.topic == n["topic"] else ""
            out.append(f"  {i}) {n['network_name']:20} as {n['alias']:14} ({role}){here}")
        out.append("  Type a number to join one." if not self.net else "  /exit first to switch to another one.")
        return out

    @command("exit", help="leaves the network but keeps the program open, so you can join another")
    async def cmd_exit(self, arg):
        return await self.leave() + [self.menu()]

    @command("quit", needs_network=False, help="says goodbye and closes the program")
    def cmd_quit(self, arg):
        self.running = False

    # --- modules ------------------------------------------------------------

    @command("module", "list", needs_network=False, help="shows available and enabled modules")
    def cmd_module_list(self, arg):
        enabled = set(self.config.modules)
        out = []
        for name, cls in sorted(self.available.items()):
            state = "running" if name in self.modules else ("enabled (restart to start)" if name in enabled
                                                             else "disabled")
            needs = f"  needs: {', '.join(cls.requires)}" if cls.requires else ""
            out.append(f"  {name:10} {state:28} {cls.title}{needs}")
        if self._missing_reported:
            out.append(f"  networks you joined also use: {', '.join(sorted(self._missing_reported))}")
        return out

    @command("module", "enable", "<NAME>", needs_network=False, help="enables a module (takes effect on restart)")
    def cmd_module_enable(self, arg):
        name = arg.strip().lower()
        if name not in self.available:
            raise CommandError(f"no module '{name}'. /module -list shows what's available.")
        wanted = list(self.config.modules)
        added = [n for n in (*self.available[name].requires, name) if n not in wanted]
        if not added:
            return f"  '{name}' is already enabled"
        self.config.set_modules(wanted + added)
        return f"  enabled {', '.join(added)}. Restart the program to start {'them' if len(added) > 1 else 'it'}."

    @command("module", "disable", "<NAME>", needs_network=False, help="disables a module (takes effect on restart)")
    def cmd_module_disable(self, arg):
        name = arg.strip().lower()
        wanted = list(self.config.modules)
        if name not in wanted:
            raise CommandError(f"'{name}' isn't enabled")
        dependents = [n for n in wanted if name in getattr(self.available.get(n), "requires", ())]
        if dependents:
            raise CommandError(f"{', '.join(dependents)} need{'s' if len(dependents) == 1 else ''} '{name}'; "
                               f"disable {'it' if len(dependents) == 1 else 'them'} first")
        self.config.set_modules([n for n in wanted if n != name])
        return f"  disabled '{name}'. Restart the program to stop it; its data stays in the network folders."

    # --- you ----------------------------------------------------------------

    @command("netuser", "set_alias", "<Alias>", help="changes your alias on this network")
    def cmd_netuser_set_alias(self, arg):
        self.net.set_alias(arg[:64])
        return f"  alias set to {self.net.alias}"

    @command("netuser", "info", help="displays your info on this network")
    def cmd_netuser_info(self, arg):
        n = self.net
        row = n.ledger.get(n.me) or {}
        out = [f"  alias:     {n.alias}",
               f"  ID:        {n.me}",
               f"  role:      {n.role_of(n.me).upper()}" + ("  (creator)" if n.me == n.founder else ""),
               f"  network:   {n.name}",
               f"  joined:    {row.get('first_con') or '-'}",
               f"  public IP: {self.api.public_ip or '(not known yet)'}"]
        for module in self.modules.values():
            out += module.user_info(n.me)
        return out

    @command("identity", "export", "<FILE>", needs_network=False,
             help="saves an encrypted backup of this device's identity")
    async def cmd_identity_export(self, arg):
        path = Path(arg.strip().strip('"')).expanduser().resolve()
        if path.exists():
            answer = await self.console.input(f"  {path} exists. Overwrite it? [y/N] ")
            if answer.strip().lower() != "y":
                return "  cancelled"
        passphrase = await self.console.input(f"Passphrase for the backup (at least {backup.MIN_PASSPHRASE} "
                                              f"characters): ", secret=True)
        if len(passphrase) < backup.MIN_PASSPHRASE:
            raise CommandError(f"the passphrase needs at least {backup.MIN_PASSPHRASE} characters")
        if await self.console.input("The same passphrase again: ", secret=True) != passphrase:
            raise CommandError("the passphrases don't match")
        write_json(path, backup.seal(self.identity.as_dict(), passphrase))
        return [f"  saved an encrypted backup of this device's identity to {path}",
                "  It holds this node's key and its networks: with it (and the passphrase) a new device can",
                "  take this node's place, admin rights included. Keep it off this device, e.g. on a USB stick."]

    @command("identity", "import", "<FILE>", needs_network=False,
             help="replaces this device's identity with a backup (then restart)")
    async def cmd_identity_import(self, arg):
        if self.net:
            raise CommandError("/exit the network first")
        path = Path(arg.strip().strip('"')).expanduser().resolve()
        try:
            sealed = read_json(path, None)
        except (OSError, ValueError) as e:
            raise CommandError(f"can't read {path}: {e}")
        if sealed is None:
            raise CommandError(f"no file {path}")
        passphrase = await self.console.input("The backup's passphrase: ", secret=True)
        data = backup.unseal(sealed, passphrase)  # ValueError if wrong: shown as '! ...'
        if not Identity.valid(data):
            raise CommandError("the backup doesn't contain a valid identity")
        if data["seed"] == self.identity.seed:
            return "  that backup is this device's current identity; nothing to do"
        names = ", ".join(n.get("network_name", "?") for n in data.get("networks", [])) or "none"
        answer = await self.console.input(
            f"  This replaces this device's identity (its key and its {len(self.identity.networks)} saved "
            f"network(s)) with the backup's (networks: {names}).\n"
            f"  Don't run the same identity on two devices at once. Type 'import' to confirm: ")
        if answer.strip().lower() != "import":
            return "  cancelled"
        old = self.identity.path.with_name(f"identity.replaced-{now()[:19].replace(':', '-')}.json")
        shutil.copyfile(self.identity.path, old)
        self.identity.replace(data)
        self.running = False  # the sidecar still holds the old key: restart to use the new one
        return [f"  identity restored from {path}. The one it replaced was kept as {old.name}.",
                "  The program will now close. Start it again to use the restored identity."]

    # --- network ------------------------------------------------------------

    @command("network", "info", help="shows the network's name, creator and mode")
    def cmd_network_info(self, arg):
        n = self.net
        days = n.settings.succession_days
        out = [f"  name:     {n.name}",
               f"  creator:  {n.name_of(n.founder)}",
               f"  mode:     {'1 (allowlist)' if n.settings.allowlist_mode else '0 (blocklist)'}",
               f"  password: {'yes' if n.requires_password else 'no'}",
               f"  succession: " + (f"after {days} days without any admin, the longest-standing member "
                                    f"becomes admin" if days else "off"),
               f"  topic:    {n.topic}",
               f"  online:   {len(n.trusted_peers())} peer(s)"]
        for module in self.modules.values():
            out += module.network_info()
        return out

    @command("network", "list", help="shows admins, members and blocked users")
    def cmd_network_list(self, arg):
        n = self.net
        blocked = set(n.blocklist.keys())
        admins = sorted(n.admin_keys() - blocked, key=lambda k: k != n.founder)  # creator first
        members = [r["identity"] for r in n.ledger.all()
                   if r["identity"] not in blocked and n.role_of(r["identity"]) == MEMBER]
        out = []
        for title, keys in (("Admins", admins), ("Members", members), ("Blocked", sorted(blocked))):
            out.append(f"  {title}:")
            if not keys:
                out.append("    (none)")
            for k in keys:
                state = "you" if k == n.me else ("online" if k in n.online else "offline")
                allowed = "  allowlisted" if k in n.allowlist else ""
                tags = " ".join(t for t in (m.peer_tags(k) for m in self.modules.values()) if t)
                out.append(f"    {short(k)}  {n.name_of(k):14} {state:8} {tags}{allowed}".rstrip())
        if n.settings.allowlist_mode:
            out.append("  (allowlist mode: only allowlisted users and admins can connect)")
        return out

    @command("network", "leave", help="same as /exit")
    async def cmd_network_leave(self, arg):
        return await self.cmd_exit(arg)

    @command("network", "sync", help="sends your data to everyone; whoever is behind catches up")
    def cmd_network_sync(self, arg):
        n = self.net
        if not n.online:
            raise CommandError("nobody else is online to sync with")
        count = n.sync()
        out = [f"  sent your data to {count} peer(s). Anything newer they have will arrive and be applied."]
        for key, f in n.files.items():
            label = FILE_LABELS.get(key) or key.replace(".", ": ")
            state = f"{len(f.all())} rows" if isinstance(f, MergedStore) else f"v{f.version}"
            out.append(f"    {label:24} {state:9} {f.meta.get('last_modified') or '-'}")
        return out

    @command("network", "set_mode", "<0|1>", admin=True, help="1 = allowlist mode, 0 = blocklist mode")
    async def cmd_network_set_mode(self, arg):
        n = self.net
        modes = {"1": 1, "0": 0, "allowlist": 1, "blocklist": 0}
        if arg.lower() not in modes:
            raise CommandError("usage: /network -set_mode 1   (allowlist)   or   /network -set_mode 0   (blocklist)")
        mode = modes[arg.lower()]
        if mode == 1:
            allowed = set(n.allowlist.keys()) | n.admin_keys()
            cut = [p for p in n.online if p not in allowed]
            if cut:
                names = ", ".join(n.name_of(p) for p in cut)
                answer = await self.console.input(f"  this disconnects {len(cut)} online user(s) not on the "
                                                  f"allowlist ({names}). Continue? [y/N] ")
                if answer.strip().lower() != "y":
                    return "  cancelled"
        await n.admin("set_mode", allowlist=mode)
        return f"  network mode set to {mode} ({'allowlist' if mode else 'blocklist'})"

    @command("network", "password", help="enters the network's password (e.g. if it was mistyped when joining)")
    async def cmd_network_password(self, arg):
        password = (await self.console.input("Network password: ", secret=True)).strip()
        if not password:
            raise CommandError("no password entered")
        topic = self.net.topic
        self.identity.update_network(topic, password_salt="", password_key="")
        return ["  reconnecting with that password..."] + await self.enter(topic, password)

    @command("network", "dissolve", admin=True, help="closes the network for everyone and deletes it here")
    async def cmd_network_dissolve(self, arg):
        n = self.net
        answer = await self.console.input(
            f"  This tells every member to leave '{n.name}' and delete its data, and can't be undone.\n"
            f"  Members offline right now only find out if they later meet a node that still has it.\n"
            f"  Type 'dissolve' to confirm: ")
        if answer.strip().lower() != "dissolve":
            return "  cancelled"
        online = len(n.trusted_peers())
        topic, name = n.topic, n.name
        await n.admin("dissolve")  # signed and pushed to everyone online
        await self.leave()          # the goodbye goes out after the push, so it arrives first
        self._forget(topic)
        return [f"  dissolved '{name}': {online} online member(s) were told to leave and delete it,",
                "  and it's been deleted from this node.", self.menu()]

    @command("network", "succession", "<DAYS|off>", admin=True,
             help="days without any admin before a member takes over (0 or off: never)")
    async def cmd_network_succession(self, arg):
        value = arg.strip().lower()
        days = 0 if value in ("off", "0") else int(value) if value.isdigit() else None
        if days is None or days > MAX_SUCCESSION_DAYS:
            raise CommandError(f"usage: /network -succession <DAYS|off>   (1 to {MAX_SUCCESSION_DAYS} days)")
        await self.net.admin("set_succession", days=days)
        if not days:
            return "  succession turned off: if every admin is gone for good, nobody can manage the network"
        return f"  succession set: after {days} days without any admin, the longest-standing member becomes admin"

    @command("network", "set_name", "<Name>", admin=True, help="renames the network")
    async def cmd_network_set_name(self, arg):
        await self.net.admin("set_name", name=arg[:64])
        return f"  network renamed to '{self.net.name}'"

    # --- access lists -------------------------------------------------------

    async def _change_list(self, name: str, flag: str, arg: str):
        action = LIST_ACTIONS[(name, flag)]
        n = self.net
        keys = [self.resolve(t) for t in self.list_payload(arg)]  # resolve all before changing anything
        out = []
        for key in keys:
            if key == n.founder and action in ("block_add", "admin_remove", "allow_remove"):
                out.append(f"  ! {n.name_of(key)} created the network and can't be blocked or demoted, skipped")
            elif key == n.me and action == "block_add":
                out.append("  ! you can't block yourself, skipped")
            else:
                await n.admin(action, identity=key, alias=n.name_of(key))
                out.append(f"  {n.describe({'action': action, 'identity': key})}")
        return out

    @command("allowlist", "append", "<ID>", admin=True, help="adds a user to the allowlist")
    async def cmd_allowlist_append(self, arg):
        return await self._change_list("allowlist", "append", arg)

    @command("allowlist", "remove", "<ID>", admin=True, help="removes a user from the allowlist")
    async def cmd_allowlist_remove(self, arg):
        return await self._change_list("allowlist", "remove", arg)

    @command("blocklist", "append", "<ID>", admin=True, help="blocks a user")
    async def cmd_blocklist_append(self, arg):
        return await self._change_list("blocklist", "append", arg)

    @command("blocklist", "remove", "<ID>", admin=True, help="unblocks a user")
    async def cmd_blocklist_remove(self, arg):
        return await self._change_list("blocklist", "remove", arg)

    @command("admin", "append", "<ID>", admin=True, help="makes a user an admin")
    async def cmd_admin_append(self, arg):
        return await self._change_list("admin", "append", arg)

    @command("admin", "remove", "<ID>", admin=True, help="removes a user's admin rights")
    async def cmd_admin_remove(self, arg):
        return await self._change_list("admin", "remove", arg)

    # --- argument helpers, also used by modules ------------------------------

    def resolve(self, token: str) -> str:
        """An ID can be the full key, a unique start of it, or the user's alias."""
        token = token.strip()
        if KEY.fullmatch(token):
            return token
        rows = self.net.ledger.all()
        by_alias = [r["identity"] for r in rows if r.get("alias", "").lower() == token.lower()]
        if len(by_alias) == 1:
            return by_alias[0]
        by_prefix = [r["identity"] for r in rows if r["identity"].startswith(token.lower())]
        if len(by_prefix) == 1:
            return by_prefix[0]
        found = len(by_alias) or len(by_prefix)
        if found:
            raise CommandError(f"'{token}' matches {found} users. Use more of their ID.")
        raise CommandError(f"no known user '{token}'. /network -list shows everyone.")

    @staticmethod
    def list_payload(payload: str) -> list[str]:
        if payload.startswith("["):
            try:
                return [str(i) for i in json.loads(payload)]
            except json.JSONDecodeError as e:
                raise CommandError(f"invalid JSON list: {e}")
        return payload.split()

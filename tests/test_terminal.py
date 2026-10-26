"""The prompt_toolkit terminal, driven through a simulated keyboard: typing,
Tab completion, history, hidden passwords, messages arriving mid-typing, the
status bar, and the fallback to the classic console."""

import asyncio

from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from core.console_classic import ClassicConsole
from core.terminal import Terminal, make_console
from tests.harness import fresh_dir, network_of


async def typed(term: Terminal, keys: str, **kwargs) -> str:
    """Type `keys` into the terminal and return the line it hands back."""
    task = asyncio.create_task(term.input("> ", **kwargs))
    await asyncio.sleep(0.2)
    for part in keys.split("\t")[:-1]:  # completion finishes asynchronously: pause after Tab, like a person
        term._keyboard.send_text(part + "\t")
        await asyncio.sleep(0.3)
    term._keyboard.send_text(keys.split("\t")[-1])
    return await asyncio.wait_for(task, 5)


async def run(t):
    base = fresh_dir("terminal")
    admin, bob = await network_of(base, "admin", "bob")
    history = base / "history.txt"

    with create_pipe_input() as keyboard:
        term = Terminal(history, admin.ctl.complete, admin.ctl.toolbar, input=keyboard, output=DummyOutput())
        term._keyboard = keyboard
        try:
            t.check("a typed command comes back", await typed(term, "/help\r", command=True) == "/help")
            got = await typed(term, "/he\t\r", command=True)
            t.check("Tab completes a command", got == "/help ", repr(got))
            got = await typed(term, "/network -set_n\t\r", command=True)
            t.check("Tab completes a flag", got == "/network -set_name ", repr(got))
            got = await typed(term, "/dm B\t\r", command=True)
            t.check("Tab completes a member's name", got == "/dm Bob ", repr(got))
            t.check("line editing works (Home, then insert)",
                    await typed(term, "elp\x1b[H/h\r", command=True) == "/help")
            t.check("Up recalls the previous command", await typed(term, "\x1b[A\r", command=True) == "/help")

            secret = await typed(term, "hunter2\r", secret=True)
            t.check("a hidden prompt still returns what was typed", secret == "hunter2")
            term.close()
            saved = history.read_text(encoding="utf-8")
            t.check("commands are kept in the history file", "/network -set_name" in saved)
            t.check("passwords and questions are not", "hunter2" not in saved)
        finally:
            term.close()

    with create_pipe_input() as keyboard:
        term = Terminal(history, admin.ctl.complete, admin.ctl.toolbar, input=keyboard, output=DummyOutput())
        try:
            task = asyncio.create_task(term.input("> ", command=True))
            await asyncio.sleep(0.2)
            keyboard.send_text("/net")
            await asyncio.sleep(0.1)
            term.show("* Bob connected (member)")  # a message arrives mid-typing
            keyboard.send_text("work -info\r")
            t.check("a message arriving mid-typing doesn't lose the typed text",
                    await asyncio.wait_for(task, 5) == "/network -info")
        finally:
            term.close()

    # Members aren't offered admin commands.
    t.check("completion only offers commands you may use",
            "/network -set_name " in admin.ctl.complete("/network -set")
            and "/network -set_name " not in bob.ctl.complete("/network -set"))
    bar = admin.ctl.toolbar()
    t.check("the status bar shows network, role and who's online", "home" in bar and "admin" in bar and "1 online" in bar, bar)

    t.check("--classic gives the original console",
            isinstance(make_console(history, admin.ctl.complete, admin.ctl.toolbar, classic=True), ClassicConsole))

    for node in (admin, bob):
        await node.close()

"""The interactive terminal, built on prompt_toolkit.

  - messages from the network appear above the line you're typing, which stays put
  - full line editing; Up/Down for command history, kept between runs (data/history.txt)
  - Tab completes commands, flags and member names (only commands you may use)
  - passwords show as * while typed
  - a status bar: network, your role, who's online, the DNS port
  - colour: errors red, network events cyan, private messages magenta, chat green

prompt_toolkit runs on the same asyncio event loop as everything else.
If it isn't installed, or this isn't an interactive terminal, make_console()
falls back to core.console_classic.
"""

import sys
from pathlib import Path
from typing import Callable

from core.console_classic import ClassicConsole

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.formatted_text import ANSI
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.patch_stdout import patch_stdout
    from prompt_toolkit.shortcuts import print_formatted_text
    from prompt_toolkit.styles import Style
except ImportError:  # not installed: the classic console is used instead
    PromptSession = None

RESET = "\x1b[0m"
COLOURS = (("!", "\x1b[31m"), ("[DM]", "\x1b[35m"), ("*", "\x1b[36m"), ("<", "\x1b[32m"))
STYLE = {"bottom-toolbar": "bg:#1f2933 #c8d1da", "prompt": "bold"}


def colour(text: str) -> str:
    """Colour each line by what it is: error, private message, event, chat."""
    out = []
    for line in text.split("\n"):
        code = next((c for start, c in COLOURS if line.lstrip().startswith(start)), None)
        out.append(f"{code}{line}{RESET}" if code else line)
    return "\n".join(out)


if PromptSession:
    class _Completer(Completer):
        def __init__(self, complete: Callable[[str], list[str]]):
            self.complete = complete

        def get_completions(self, document, complete_event):
            before = document.text_before_cursor
            for line in self.complete(before):
                # Each suggestion is the whole line up to the cursor; show just its last word.
                yield Completion(line, start_position=-len(before), display=line.rstrip().rsplit(" ", 1)[-1])


class Terminal:
    def __init__(self, history_file: Path, complete: Callable[[str], list[str]], toolbar: Callable[[], str],
                 input=None, output=None):
        """input/output: prompt_toolkit input and output to use instead of the
        real terminal (tests drive the terminal through them)."""
        history_file.parent.mkdir(parents=True, exist_ok=True)
        style = Style.from_dict(STYLE)
        io = {"input": input, "output": output}
        # Commands: history, completion, status bar. Questions (alias, passwords,
        # confirmations) get a plain session, so they never end up in the history.
        self.commands = PromptSession(history=FileHistory(str(history_file)), completer=_Completer(complete),
                                      complete_while_typing=False, bottom_toolbar=lambda: " " + toolbar(),
                                      refresh_interval=1, style=style, **io)
        self.questions = PromptSession(style=style, **io)
        self._output = output
        # In a real terminal, anything printed shows above the prompt.
        self._patch = patch_stdout(raw=True) if output is None else None
        if self._patch:
            self._patch.__enter__()
        self._active = None

    async def input(self, prompt: str = "", secret: bool = False, command: bool = False) -> str:
        """The next typed line. Ctrl+C raises KeyboardInterrupt, Ctrl+D EOFError."""
        session = self.commands if command else self.questions
        self._active = session
        try:
            return await session.prompt_async([("class:prompt", prompt)], is_password=secret)
        finally:
            self._active = None

    def show(self, text: str):
        """A message from the network: printed above the line being typed."""
        self.write(text)

    def write(self, text: str):
        """A command's output."""
        print_formatted_text(ANSI(colour(text)), **({"output": self._output} if self._output else {}))

    def stop(self):
        """End the command loop as if input had ended."""
        if self._active and self._active.app.is_running:
            self._active.app.exit(exception=EOFError())

    def close(self):
        if self._patch:
            self._patch.__exit__(None, None, None)
            self._patch = None


def make_console(history_file: Path, complete: Callable[[str], list[str]], toolbar: Callable[[], str],
                 classic: bool = False):
    """The prompt_toolkit terminal when possible, otherwise the classic console."""
    if classic or PromptSession is None or not (sys.stdin.isatty() and sys.stdout.isatty()):
        if PromptSession is None and not classic:
            print("(prompt_toolkit isn't installed: using the classic console. pip install -r requirements.txt)")
        return ClassicConsole()
    return Terminal(history_file, complete, toolbar)

"""Running without a keyboard (python main.py --headless), e.g. as a service on
a Raspberry Pi or home server, plus the log file every mode writes.

Headless, there is no prompt: the node joins a saved network at start and
keeps it up to date until it's stopped (Ctrl+C, SIGTERM, or the service
manager). What it would have shown goes to the log file and to stdout, so
`journalctl` and similar tools see it too.
"""

import asyncio
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

log = logging.getLogger("dddns")


def setup_logging(path: Path, to_stdout: bool):
    """Log to `path` (rotated: at most 3 files of 1 MB), and to stdout if asked."""
    path.parent.mkdir(parents=True, exist_ok=True)
    log.setLevel(logging.INFO)
    log.propagate = False
    for handler in list(log.handlers):
        log.removeHandler(handler)
    to_file = RotatingFileHandler(path, maxBytes=1024 * 1024, backupCount=2, encoding="utf-8")
    to_file.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%Y-%m-%d %H:%M:%S"))
    log.addHandler(to_file)
    if to_stdout:
        to_out = logging.StreamHandler(sys.stdout)
        to_out.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))
        log.addHandler(to_out)


class HeadlessConsole:
    """The console interface (see core.terminal) with nobody at the keyboard."""

    headless = True

    def __init__(self):
        self._stopped = asyncio.Event()

    async def input(self, prompt: str = "", secret: bool = False, command: bool = False) -> str:
        """The command loop waits here until the node is stopped. Questions
        can't be answered, so they end the command that asked them."""
        if command:
            await self._stopped.wait()
        raise EOFError

    def show(self, text: str):
        """Network messages: the controller already logs them."""

    def write(self, text: str):
        for line in text.strip("\n").split("\n"):
            log.info(line)

    def stop(self):
        self._stopped.set()

    def close(self):
        pass

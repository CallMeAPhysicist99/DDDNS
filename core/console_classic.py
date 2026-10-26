"""The classic console: one typed line at a time, no line editing.

This was the program's original console. It's kept as a fallback for
core.terminal: it's used with `python main.py --classic`, and automatically
when prompt_toolkit isn't installed or input/output isn't an interactive
terminal (piped or redirected).

asyncio can't wait for keyboard input on Windows, so one helper thread reads
typed lines and hands them to the event loop.
"""

import asyncio
import os
import shutil
import sys
import threading


def clear_line_code() -> str | None:
    """What to print to wipe the current terminal line (the prompt, and anything
    half-typed) before a message is shown. None when output isn't a terminal."""
    if not sys.stdout.isatty():
        return None
    if os.name == "nt" and not enable_windows_vt():
        # No erase code: overwrite the line with spaces instead.
        return "\r" + " " * (shutil.get_terminal_size().columns - 1) + "\r"
    return "\r\x1b[2K"  # back to the line's start, erase the whole line


def enable_windows_vt() -> bool:
    """The classic Windows console only understands escape codes (erase line,
    colours, cursor moves) once "virtual terminal processing" is switched on."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # stdout
        mode = ctypes.c_uint32()
        return bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                    and kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (OSError, AttributeError):
        return False


class ClassicConsole:
    """Typed lines, delivered to the event loop."""

    def __init__(self):
        self._loop = asyncio.get_running_loop()
        self._lines: asyncio.Queue = asyncio.Queue()
        self._clear = clear_line_code()
        self.prompt = ""
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        while True:
            line = sys.stdin.readline()
            self._loop.call_soon_threadsafe(self._lines.put_nowait, line or None)
            if not line:
                return  # end of input

    async def input(self, prompt: str = "", secret: bool = False, command: bool = False) -> str:
        """The next typed line. This console can't hide input, so a secret
        prompt says it will show."""
        self.prompt = prompt
        print(prompt + ("(it shows as you type) " if secret else ""), end="", flush=True)
        line = await self._lines.get()
        if line is None:
            raise EOFError
        return line.lstrip("﻿").rstrip("\r\n")  # piped input on Windows can start with a BOM

    def show(self, text: str):
        """A message that arrived while the prompt is waiting: wipe the prompt
        line, print the message, then put the prompt back under it."""
        if self._clear is None:
            print(text, flush=True)  # not a terminal (piped/logged): just the message
        else:
            print(f"{self._clear}{text}\n{self.prompt}", end="", flush=True)

    def write(self, text: str):
        """A command's output."""
        print(text, flush=True)

    def stop(self):
        """End the command loop as if input had ended."""
        self._lines.put_nowait(None)

    def close(self):
        pass

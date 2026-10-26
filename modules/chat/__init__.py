"""Chat module: private and broadcast messages between online members.
A small module, and a good example of one: two commands and one message handler.
"""

from core.module import CommandError, Module, command

MAX_MESSAGE = 2000


class ChatModule(Module):
    name = "chat"
    title = "Messages"

    async def on_message(self, peer: str, kind: str, data: dict):
        text = str(data.get("text", ""))[:MAX_MESSAGE]
        tag = "[DM] " if kind == "dm" else ""
        self.notify(f"{tag}<{self.net.name_of(peer)}> {text}")

    @command("dm", args="<ID> <msg>", help="sends a private message to one online user")
    def cmd_dm(self, arg):
        parts = arg.split(maxsplit=1)
        if len(parts) < 2:
            raise CommandError("usage: /dm <ID> <msg>")
        self.send(self.controller.resolve(parts[0]), "dm", {"text": parts[1][:MAX_MESSAGE]})

    @command("broadcast", args="<msg>", help="sends a message to everyone online")
    def cmd_broadcast(self, arg):
        self.broadcast("broadcast", {"text": arg[:MAX_MESSAGE]})


MODULE = ChatModule

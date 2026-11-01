"""Canned replacements: never resolve a name, connect or fetch any supplied URL."""
import hashlib
import json

from cowrie.shell.command import HoneyPotCommand


class CommandLabNetwork(HoneyPotCommand):
    def start(self):
        # Emit only when the pinned Cowrie shell actually dispatches this canned
        # handler. The event uses the session-bound emitter, never a caller IP.
        events = getattr(getattr(self, "protocol", None), "events", None)
        args = [str(part)[:4096] for part in getattr(self, "args", [])]
        args_digest = hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest()
        if events is not None:
            events.dispatch("dgsoc.network.denied", "Denied network tool command", command="network tool",
                            attempt_sha256=args_digest)
        self.write("Network access is unavailable on this host.\n")
        self.exit_code = 1
        self.exit()


commands = {}
for name in ("wget", "curl", "nc", "netcat", "ncat", "ftpget", "ftp", "tftp",
             "ping", "ping6", "dig", "nslookup", "host", "netstat", "ssh", "scp", "sftp"):
    for prefix in ("", "/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/"):
        commands[prefix + name] = CommandLabNetwork

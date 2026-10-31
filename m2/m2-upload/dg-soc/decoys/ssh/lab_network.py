"""Canned replacements: never resolve a name, connect or fetch any supplied URL."""
from cowrie.shell.command import HoneyPotCommand


class CommandLabNetwork(HoneyPotCommand):
    def start(self):
        self.write("Network access is unavailable on this host.\n")
        self.exit_code = 1
        self.exit()


commands = {}
for name in ("wget", "curl", "nc", "netcat", "ncat", "ftpget", "ftp", "tftp",
             "ping", "ping6", "dig", "nslookup", "host", "netstat", "ssh", "scp", "sftp"):
    for prefix in ("", "/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/"):
        commands[prefix + name] = CommandLabNetwork

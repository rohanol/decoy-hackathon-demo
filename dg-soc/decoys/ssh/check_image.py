#!/usr/bin/env python3
"""Offline integration check of the exact image. No SSH service or port is opened."""
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "cowrie/cowrie@sha256:baf351038db967704dfa39f7ce860e8875c9456cdab72a9d3257c4247211050d"
CODE = r'''
import socket
from types import SimpleNamespace
from cowrie.core.config import CowrieConfig
CowrieConfig.read(["/lab/cowrie.cfg"])
from cowrie.shell.pwd import Passwd
user = Passwd().getpwnam("dg_demo")
assert user["pw_dir"] == "/home/dg_demo" and user["pw_uid"] == 1000
from cowrie.shell.fs import HoneyPotFilesystem
fs = HoneyPotFilesystem("linux-x64-lsb", user["pw_dir"])
assert fs.exists("/home/dg_demo/notes.txt")
assert "notes.txt" in fs.listdir("/home/dg_demo")
assert fs.file_contents("/home/dg_demo/notes.txt") == open("/lab/notes.txt", "rb").read()
# The real protocol builds its dispatch map from the operator's lab registry.
from cowrie.shell.protocol import HoneyPotBaseProtocol
from cowrie.commands.lab_network import CommandLabNetwork
def forbidden(*args, **kwargs):
    raise AssertionError("A canned command attempted DNS/network access")
socket.getaddrinfo = socket.gethostbyname = socket.gethostbyaddr = forbidden
from twisted.internet import reactor
reactor.resolve = reactor.connectTCP = reactor.connectSSL = reactor.listenUDP = forbidden
for name in ("wget", "curl", "nc", "ftpget", "tftp", "dig", "ping", "netstat", "/usr/bin/wget", "/bin/curl"):
    cls = HoneyPotBaseProtocol.commands[name]
    assert cls is CommandLabNetwork
    command = cls.__new__(cls)
    command.args = ["https://example.invalid/not-fetched"]
    emitted = []
    command.protocol = SimpleNamespace(events=SimpleNamespace(dispatch=lambda *args, **kwargs: emitted.append((args, kwargs))))
    result = []
    command.write = result.append
    command.exit = lambda: None
    command.start()
    assert command.exit_code == 1 and result == ["Network access is unavailable on this host.\n"]
    assert emitted and emitted[0][0][0] == "dgsoc.network.denied"
    assert emitted[0][1]["command"] == "network tool"
    assert len(emitted[0][1]["attempt_sha256"]) == 64
print("PASS: real Cowrie passwd loader and filesystem read the embedded user/note; network commands are canned with DNS/connect traps")
'''


def main():
    with tempfile.TemporaryDirectory(prefix="dg-image-check-") as directory:
        temp = Path(directory)
        temp.chmod(0o755)
        cfg = (ROOT / "deployment/cowrie/cowrie.cfg").read_text().replace("/cowrie/cowrie-git/custom/fs.pickle", "/lab/fs.pickle")
        (temp / "cowrie.cfg").write_text(cfg)
        files = {
            "fs.pickle": ROOT / "decoys/ssh/fs.pickle",
            "notes.txt": ROOT / "deployment/cowrie/honeyfs/home/dg_demo/notes.txt",
            "registry.py": ROOT / "decoys/ssh/lab_command_registry.py",
            "network.py": ROOT / "decoys/ssh/lab_network.py",
        }
        for name, source in files.items():
            (temp / name).write_bytes(source.read_bytes())
        for path in temp.iterdir():
            path.chmod(0o644)
        args = ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                "--mount", f"type=bind,src={temp},dst=/lab,readonly"]
        for source, destination in [("registry.py", "__init__.py"), ("network.py", "lab_network.py")]:
            args += ["--mount", f"type=bind,src={temp/source},dst=/cowrie/cowrie-git/src/cowrie/commands/{destination},readonly"]
        subprocess.run(args + [IMAGE, "-c", CODE], check=True)


if __name__ == "__main__":
    main()

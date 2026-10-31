#!/usr/bin/env python3
"""Prepare the pinned shell-less image using stopped containers, never docker run."""
import configparser
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINNED = "cowrie/cowrie@sha256:baf351038db967704dfa39f7ce860e8875c9456cdab72a9d3257c4247211050d"
PICKLE = "/cowrie/cowrie-git/src/cowrie/data/fs.pickle"
DIST = "/cowrie/cowrie-git/src/cowrie/data/etc/cowrie.cfg.dist"
IMAGE_LINE = re.compile(r"^(\s*image:\s*)cowrie/cowrie[^\s#]*", re.M)


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def validate_config(dist, overrides):
    known, section = set(), None
    for line in dist.read_text().splitlines():
        stanza = re.match(r"\s*\[([^]]+)\]", line)
        option = re.match(r"\s*#?\s*([\w]+)\s*=", line)
        if stanza:
            section = stanza[1]
        elif option:
            known.add((section, option[1]))
    config = configparser.ConfigParser(interpolation=None)
    config.read(overrides)
    unknown = {(s, k) for s in config.sections() for k in config[s]} - known
    if unknown:
        raise ValueError(f"Unknown Cowrie options: {sorted(unknown)}")


def prepare(mode):
    compose = ROOT / "deployment/docker-compose.yml"
    text = compose.read_text()
    matches = list(IMAGE_LINE.finditer(text))
    if len(matches) != 1:
        raise ValueError("Expected exactly one Cowrie image line")
    current = matches[0][0].split("image:", 1)[1].strip()
    image = os.environ.get("COWRIE_TAG", PINNED) if mode == "pin" else current
    if not image.startswith("cowrie/cowrie"):
        raise ValueError("Only the Cowrie repository is supported")
    if mode == "pin":
        subprocess.run(["docker", "pull", image], check=True)
        digests = __import__("json").loads(docker("image", "inspect", "--format", "{{json .RepoDigests}}", image))
        image = next((d for d in digests if re.fullmatch(r"cowrie/cowrie@sha256:[0-9a-f]{64}", d)), None)
    if not image or not re.fullmatch(r"cowrie/cowrie@sha256:[0-9a-f]{64}", image):
        raise ValueError("Pin a verified Cowrie digest before building the filesystem")
    # Nothing is started: no shell or attacker-controlled network activity.
    cid = docker("create", image)
    try:
        with tempfile.TemporaryDirectory(prefix="dg-cowrie-") as directory:
            temp = Path(directory)
            subprocess.run(["docker", "cp", f"{cid}:{DIST}", str(temp / "cowrie.cfg.dist")], check=True)
            validate_config(temp / "cowrie.cfg.dist", ROOT / "deployment/cowrie/cowrie.cfg")
            if mode == "build":
                subprocess.run(["docker", "cp", f"{cid}:{PICKLE}", str(temp / "base.pickle")], check=True)
                subprocess.run([sys.executable, str(ROOT / "decoys/ssh/patch_fs.py"),
                    str(temp / "base.pickle"), str(temp / "fs.pickle"),
                    str(ROOT / "deployment/cowrie/honeyfs/home/dg_demo/notes.txt")], check=True)
                # Make output readable by image UID 999 and replace it atomically.
                target = ROOT / "decoys/ssh/fs.pickle"
                staged = target.with_suffix(".pickle.tmp")
                staged.write_bytes((temp / "fs.pickle").read_bytes())
                staged.chmod(0o644)
                staged.replace(target)
            else:
                # Only update compose once extraction and option validation succeed.
                compose.write_text(IMAGE_LINE.sub(lambda m: m[1] + image, text, count=1))
    finally:
        subprocess.run(["docker", "rm", "-f", cid], check=True, stdout=subprocess.DEVNULL)
    print(f"PASS: {mode}; pinned image paths and all configured options verified: {image}")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"pin", "build"}:
        raise SystemExit("Usage: cowrie_image.py pin|build")
    prepare(sys.argv[1])

#!/usr/bin/env python3
"""Patch only a trusted, digest-pinned Cowrie image pickle, never uploaded data."""
import pickle
import sys
import time
from pathlib import Path

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_DIR, T_FILE = 1, 2
PASSWD_LINE = b"dg_demo:x:1000:1000:Demo user:/home/dg_demo:/bin/bash\n"


def find(node, name):
    return next((child for child in node[A_CONTENTS] if child[A_NAME] == name), None)


def ensure_dir(parent, name, now):
    node = find(parent, name)
    if node is None:
        owner = 1000 if name == "dg_demo" else 0
        node = [name, T_DIR, owner, owner, 4096, 0o40755, now, [], None, None]
        parent[A_CONTENTS].append(node)
    if node[A_TYPE] != T_DIR:
        raise ValueError(f"{name} is not a directory")
    return node


def write_file(parent, name, content, now, owner=0):
    node = find(parent, name)
    if node is None:
        node = [name, T_FILE, owner, owner, len(content), 0o100644, now, content, None, None]
        parent[A_CONTENTS].append(node)
    elif node[A_TYPE] != T_FILE:
        raise ValueError(f"{name} is not a regular file")
    node[A_CONTENTS], node[A_SIZE], node[A_REALFILE] = content, len(content), None
    node[A_UID] = node[A_GID] = owner
    return node


def patch(root, notes, now):
    if not isinstance(notes, bytes):
        raise TypeError("Pass note bytes, not just their length")
    etc = ensure_dir(root, "etc", now)
    passwd = find(etc, "passwd")
    previous = passwd[A_CONTENTS] if passwd else b""
    if not isinstance(previous, bytes):
        raise ValueError("Trusted image passwd must have embedded bytes")
    # Preserve all other image users and replace/add exactly one demo entry.
    lines = [line for line in previous.splitlines() if not line.startswith(b"dg_demo:")]
    write_file(etc, "passwd", b"\n".join(lines) + (b"\n" if lines else b"") + PASSWD_LINE, now)
    home = ensure_dir(root, "home", now)
    user = ensure_dir(home, "dg_demo", now)
    write_file(user, "notes.txt", notes, now, owner=1000)
    return root


def verify(path, notes):
    with open(path, "rb") as stream:
        root = pickle.load(stream)  # trusted image or our own generated output only
    note = find(find(find(root, "home"), "dg_demo"), "notes.txt")
    passwd = find(find(root, "etc"), "passwd")
    assert note[A_TYPE] == T_FILE and note[A_CONTENTS] == notes and note[A_SIZE] == len(notes)
    assert passwd[A_CONTENTS].splitlines().count(PASSWD_LINE.rstrip(b"\n")) == 1
    assert note[A_REALFILE] is None
    return note


def main(argv):
    if len(argv) != 4:
        print("Usage: patch_fs.py TRUSTED_IMAGE.pickle OUTPUT.pickle notes.txt", file=sys.stderr)
        return 2
    source, destination, notes_path = map(Path, argv[1:])
    notes = notes_path.read_bytes()
    with source.open("rb") as stream:
        root = pickle.load(stream)  # only run against the verified pinned image
    patch(root, notes, time.time())
    destination.write_bytes(pickle.dumps(root))
    verify(destination, notes)
    print(f"OK: embedded notes.txt ({len(notes)} bytes) and persistent dg_demo passwd entry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

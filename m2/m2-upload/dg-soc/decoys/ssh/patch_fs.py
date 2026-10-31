#!/usr/bin/env python3
"""Add /home/dg_demo/notes.txt to Cowrie's fake filesystem pickle so `ls` and `cat` show it. Owner: M2.

Why: honeyfs only supplies file CONTENT. A file must also be an entry in fs.pickle, or `ls` will not list it.

Usage (see build_fs.sh, which extracts the pickle from the pinned image and runs this):
    python3 patch_fs.py IN.pickle OUT.pickle ../../deployment/cowrie/honeyfs/home/dg_demo/notes.txt

The pickle is Cowrie's own plain nested-list tree, taken from the image we pin. Only load pickles you
extracted from that image yourself, never one received from someone else.
Node layout (from Cowrie's shell/fs.py, verify against your pinned image):
  [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
  type: 0 link, 1 directory, 2 file. A directory's `contents` is a list of child nodes.
The script verifies its own result and exits 1 if the entry is not there after reload.
"""
import pickle
import sys
import time

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_DIR, T_FILE = 1, 2
UID = GID = 1000  # dg_demo


def find(node, name):
    for child in node[A_CONTENTS]:
        if child[A_NAME] == name:
            return child
    return None


def ensure_dir(parent, name, now):
    node = find(parent, name)
    if node is None:
        node = [name, T_DIR, UID if name == "dg_demo" else 0, GID if name == "dg_demo" else 0, 4096, 0o40755, now, [], None, None]
        parent[A_CONTENTS].append(node)
    elif node[A_TYPE] != T_DIR:
        raise SystemExit(f"{name} exists and is not a directory")
    return node


def patch(root, content_len, now):
    home = ensure_dir(root, "home", now)
    user = ensure_dir(home, "dg_demo", now)
    note = find(user, "notes.txt")
    if note is None:
        user[A_CONTENTS].append(["notes.txt", T_FILE, UID, GID, content_len, 0o100644, now, [], None, None])
    else:
        note[A_SIZE] = content_len
    return root


def verify(path, content_len):
    with open(path, "rb") as fh:
        root = pickle.load(fh)  # noqa: S301 - our own image's file, see docstring
    note = find(find(find(root, "home"), "dg_demo"), "notes.txt")
    assert note and note[A_TYPE] == T_FILE and note[A_SIZE] == content_len, "notes.txt entry missing or wrong size"
    return note


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    src, dst, notes = argv[1:]
    content_len = len(open(notes, "rb").read())
    with open(src, "rb") as fh:
        root = pickle.load(fh)  # noqa: S301
    patch(root, content_len, time.time())
    with open(dst, "wb") as fh:
        pickle.dump(root, fh)
    try:
        note = verify(dst, content_len)
    except (AssertionError, TypeError) as exc:
        print("VERIFY FAILED:", exc)
        return 1
    print(f"OK: /home/dg_demo/notes.txt present, size={note[A_SIZE]} bytes, mode={oct(note[A_MODE])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

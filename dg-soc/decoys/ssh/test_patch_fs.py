import pickle
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import patch_fs as pf


def fake_root():
    return ["/", pf.T_DIR, 0, 0, 4096, 0o40755, 0, [], None, None]


def test_contents_and_persistent_user_are_embedded(tmp_path):
    root = pf.patch(fake_root(), b"synthetic trail\n", 1.0)
    target = tmp_path / "fs.pickle"
    target.write_bytes(pickle.dumps(root))
    assert pf.verify(target, b"synthetic trail\n")[pf.A_UID] == 1000


def test_idempotent_preserves_other_users_and_updates_contents():
    root = pf.patch(fake_root(), b"old", 1.0)
    passwd = pf.find(pf.find(root, "etc"), "passwd")
    passwd[pf.A_CONTENTS] = b"root:x:0:0:root:/root:/bin/bash\n" + pf.PASSWD_LINE
    pf.patch(root, b"replacement", 2.0)
    user = pf.find(pf.find(root, "home"), "dg_demo")
    assert len(user[pf.A_CONTENTS]) == 1
    assert pf.find(user, "notes.txt")[pf.A_CONTENTS] == b"replacement"
    assert passwd[pf.A_CONTENTS].startswith(b"root:")
    assert sum(line.startswith(b"dg_demo:") for line in passwd[pf.A_CONTENTS].splitlines()) == 1


def test_size_only_patch_is_rejected():
    with pytest.raises(TypeError):
        pf.patch(fake_root(), 123, 1.0)


def test_nonembedded_passwd_is_not_silently_destroyed():
    root = pf.patch(fake_root(), b"note", 1.0)
    pf.find(pf.find(root, "etc"), "passwd")[pf.A_CONTENTS] = []
    with pytest.raises(ValueError):
        pf.patch(root, b"note", 1.0)


def test_cli_uses_real_note_file(tmp_path):
    source, output = tmp_path / "in.pickle", tmp_path / "out.pickle"
    source.write_bytes(pickle.dumps(fake_root()))
    notes = HERE.parents[1] / "deployment/cowrie/honeyfs/home/dg_demo/notes.txt"
    result = subprocess.run([sys.executable, str(HERE / "patch_fs.py"), str(source), str(output), str(notes)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    pf.verify(output, notes.read_bytes())

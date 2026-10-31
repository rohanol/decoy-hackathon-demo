import pickle
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import patch_fs as pf  # noqa: E402


def fake_root():
    return ["/", pf.T_DIR, 0, 0, 4096, 0o40755, 0, [["etc", pf.T_DIR, 0, 0, 4096, 0o40755, 0, [], None, None]], None, None]


def test_adds_dir_and_file_with_right_size():
    root = pf.patch(fake_root(), 123, 1.0)
    note = pf.find(pf.find(pf.find(root, "home"), "dg_demo"), "notes.txt")
    assert note[pf.A_SIZE] == 123 and note[pf.A_TYPE] == pf.T_FILE and note[pf.A_UID] == 1000
    assert pf.find(root, "etc") is not None  # existing tree untouched


def test_idempotent_and_updates_size():
    root = pf.patch(pf.patch(fake_root(), 10, 1.0), 99, 2.0)
    user = pf.find(pf.find(root, "home"), "dg_demo")
    assert len([c for c in user[pf.A_CONTENTS] if c[pf.A_NAME] == "notes.txt"]) == 1
    assert pf.find(user, "notes.txt")[pf.A_SIZE] == 99


def test_cli_end_to_end(tmp_path):
    src, dst = tmp_path / "in.pickle", tmp_path / "out.pickle"
    src.write_bytes(pickle.dumps(fake_root()))
    notes = HERE.parents[1] / "deployment" / "cowrie" / "honeyfs" / "home" / "dg_demo" / "notes.txt"
    res = subprocess.run([sys.executable, str(HERE / "patch_fs.py"), str(src), str(dst), str(notes)], capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert f"size={notes.stat().st_size}" in res.stdout

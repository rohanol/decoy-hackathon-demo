import pickle
import contextlib
import io
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import patch_fs as pf  # noqa: E402


def fake_root():
    passwd = ["passwd", pf.T_FILE, 0, 0, 32, 0o100644, 0, b"root:x:0:0:root:/root:/bin/sh\n", None, None]
    etc = ["etc", pf.T_DIR, 0, 0, 4096, 0o40755, 0, [passwd], None, None]
    return ["/", pf.T_DIR, 0, 0, 4096, 0o40755, 0, [etc], None, None]


def test_adds_dir_and_file_with_right_size():
    contents = b"Test notes\n"
    root = pf.patch(fake_root(), contents, 1.0)
    note = pf.find(pf.find(pf.find(root, "home"), "dg_demo"), "notes.txt")
    assert note[pf.A_SIZE] == len(contents) and note[pf.A_TYPE] == pf.T_FILE and note[pf.A_UID] == 1000
    assert note[pf.A_CONTENTS] == contents
    passwd = pf.find(pf.find(root, "etc"), "passwd")
    assert b"dg_demo:x:1000:1000:" in passwd[pf.A_CONTENTS]
    assert pf.find(root, "etc") is not None  # existing tree untouched


def test_idempotent_and_updates_size():
    root = pf.patch(pf.patch(fake_root(), b"1234567890", 1.0), b"updated", 2.0)
    user = pf.find(pf.find(root, "home"), "dg_demo")
    assert len([c for c in user[pf.A_CONTENTS] if c[pf.A_NAME] == "notes.txt"]) == 1
    assert pf.find(user, "notes.txt")[pf.A_SIZE] == 7
    assert pf.find(user, "notes.txt")[pf.A_CONTENTS] == b"updated"
    passwd = pf.find(pf.find(root, "etc"), "passwd")[pf.A_CONTENTS]
    assert passwd.count(b"dg_demo:x:1000:1000:") == 1


def test_cli_end_to_end(tmp_path):
    src, dst = tmp_path / "in.pickle", tmp_path / "out.pickle"
    src.write_bytes(pickle.dumps(fake_root()))
    notes = HERE.parents[1] / "deployment" / "cowrie" / "honeyfs" / "home" / "dg_demo" / "notes.txt"
    old_argv = sys.argv
    output = io.StringIO()
    try:
        sys.argv = [str(HERE / "patch_fs.py"), str(src), str(dst), str(notes)]
        with contextlib.redirect_stdout(output):
            try:
                runpy.run_path(str(HERE / "patch_fs.py"), run_name="__main__")
            except SystemExit as exc:
                assert exc.code == 0
    finally:
        sys.argv = old_argv
    assert str(notes.stat().st_size) in output.getvalue()

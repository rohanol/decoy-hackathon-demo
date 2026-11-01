from pathlib import Path
from zipfile import ZipFile


def test_backup_bait_is_only_plain_text_and_synthetic_csv():
    archive = Path(__file__).parent / "assets" / "backup.zip"
    with ZipFile(archive) as zf:
        names = set(zf.namelist())
        assert names == {"README.txt", "accounts.csv"}
        assert all(Path(name).suffix.lower() in {".txt", ".csv"} for name in names)
        csv = zf.read("accounts.csv").decode("utf-8")
        assert "DGLAB_EXAMPLE_ONLY" in csv
        assert "EXAMPLE_NOT_A_CREDENTIAL" in csv
        assert "dglab.example.com" in csv
        assert "@cdac.in" not in csv.lower()

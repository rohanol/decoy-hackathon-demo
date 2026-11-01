"""Deterministic inert archive; metadata never includes its secret values."""
import hashlib
import io
import zipfile

DB_PASSWORD = "DGLAB-DB-Reports-2026"
SMB_PASSWORD = "DGLAB-SMB-Backup-2026"
TOKEN_IDS = ["tok_db_01", "tok_smb_01"]
ASSET_ID = "web:/backup/backup.zip"


def build_backup(customer_data):
    files = {
        "README.txt": b"Research operations backup. All accounts and data are fictional.\n",
        "admin-secrets.txt": b"Service inventory: database settings and share accounts are included separately.\n",
        "db_settings.txt": ("HOST=192.168.77.20\nPORT=3306\nUSER=svc_reports\nPASSWORD=" + DB_PASSWORD + "\n").encode(),
        "share_accounts.csv": ("host,share,username,password\n192.168.77.20,backups,backup_ops," + SMB_PASSWORD + "\n").encode(),
        "customer_data.csv": customer_data,
    }
    associations = {"db_settings.txt": ["tok_db_01"], "share_accounts.csv": ["tok_smb_01"]}
    stream, entries = io.BytesIO(), []
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            entry = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
            metadata = {"name": name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            if name in associations:
                metadata["honeytoken_ids"] = associations[name]
            entries.append(metadata)
    data = stream.getvalue()
    return data, {"format": "zip", "compression": "deflate", "entries": entries,
                  "contains_executable": False, "auto_run": False}

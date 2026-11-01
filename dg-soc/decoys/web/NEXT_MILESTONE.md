# Direct Kali ZIP bait

The current release preserves the original Operations Portal appearance on
192.168.77.20:8080. Web schema 1.2 enables `/backup/backup.zip`; the 1.0/1.1
compatibility modes return 404 for it. There is no theme switch, gateway proxy
context or normal demo app in this runtime.

The deterministic archive has five regular UTF-8 text/CSV files: README.txt,
admin-secrets.txt, customer_data.csv, db_settings.txt and share_accounts.csv.
The last two plant the lab-only MySQL and SMB credentials. Inventory stores
token hashes; native challenge-response services store protocol verifiers.
There are no executable entries, paths, symlinks, nested archives or beacons.

A successful GET emits request, synthetic-file and bait records sharing a
request ID, with a fresh issuance ID and archive/entry digests. HEAD, denied
requests and log failures do not claim serving. Transfer completion remains
unknown: application logging does not prove client receipt or extraction.
Later credential proof links to eligible servings; repeated static credentials
retain ambiguous attribution rather than selecting a person or issuance.

See deployment/KALI_FOUR_RUNBOOK.md for the integrated adapter, backend,
original SOC and four-service Compose override. Tests:
`python -m pytest tests/e2e/test_kali_zip.py -q`.

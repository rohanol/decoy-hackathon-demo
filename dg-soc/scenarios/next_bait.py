"""Manual authorised two-laptop probe. Fixed lab target; inert archive only."""
import argparse
import io
import json
import zipfile
from http.cookiejar import CookieJar
from urllib.request import HTTPCookieProcessor, ProxyHandler, build_opener


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--gateway-port", type=int, default=8081)
    parser.add_argument("--mysql-port", type=int, default=3306)
    parser.add_argument("--exercise-failures", action="store_true", help="five synthetic failed database logins for R11")
    args = parser.parse_args()
    if args.target != "192.168.77.20":
        parser.error("Refusing: only isolated lab target 192.168.77.20 is allowed")
    if not (1 <= args.gateway_port <= 65535 and 1 <= args.mysql_port <= 65535):
        parser.error("Invalid port")
    import pymysql  # dev dependency; never downloaded automatically by this probe
    base = f"http://192.168.77.20:{args.gateway_port}"
    browser = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
    with browser.open(base + "/", timeout=5) as response:
        assert response.status == 200
        response.read(65536)
    with browser.open(base + "/backup/backup.zip", timeout=5) as response:
        assert response.status == 200 and response.headers.get_content_type() == "application/zip"
        data = response.read(65537)
    if len(data) > 65536:
        raise ValueError("Archive exceeds fixed lab probe budget")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        expected = {"README.txt", "admin-secrets.txt", "db_settings.txt", "share_accounts.csv", "customer_data.csv"}
        if set(archive.namelist()) != expected or len(archive.infolist()) != len(expected):
            raise ValueError("Unexpected archive entries")
        if sum(entry.file_size for entry in archive.infolist()) > 16384:
            raise ValueError("Archive expansion exceeds lab budget")
        # Read text in memory. No extractall, shell command, script or execution.
        settings = dict(line.split("=", 1) for line in archive.read("db_settings.txt").decode().splitlines() if "=" in line)
        if settings.get("HOST") != "192.168.77.20" or settings.get("USER") != "svc_reports":
            raise ValueError("Unexpected database destination/account")
        password = settings.get("PASSWORD", "")
        if not password.startswith("DGLAB-") or len(password) > 128:
            raise ValueError("Expected synthetic lab credential")
    def connect(value):
        return pymysql.connect(host="192.168.77.20", port=args.mysql_port, user="svc_reports", password=value,
                               connect_timeout=3, read_timeout=3, write_timeout=3)
    failures = 0
    if args.exercise_failures:
        for _ in range(5):
            try:
                connection = connect("DGLAB-Invalid-2026")
            except pymysql.err.OperationalError as error:
                if error.args[0] != 1045:
                    raise
                failures += 1
            else:
                connection.close()
                raise AssertionError("Wrong planted credential unexpectedly accepted")
    connection = connect(password)
    try:
        with connection.cursor() as cursor:
            try:
                cursor.execute("SELECT 1")
            except pymysql.err.OperationalError as error:
                if error.args[0] != 1142:
                    raise
            else:
                raise AssertionError("Data query unexpectedly accepted")
    finally:
        connection.close()
    print(json.dumps({"archive_response": 200, "archive_bytes": len(data), "inert_entries": len(expected),
                      "database_handshake": "emulated_success", "sql_command": "refused_1142",
                      "synthetic_failed_logins": failures,
                      "note": "Inspect actual SOC evidence; this probe does not prove identity, extraction, or malware."}))


if __name__ == "__main__":
    main()

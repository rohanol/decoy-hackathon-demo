#!/usr/bin/env python3
"""Bounded physical-lab acceptance: attacker traffic + local SOC verification.

Only 192.168.77.10 -> 192.168.77.20. No dependency downloads, real exploits,
malware, direct event injection, host state deletion or remote SOC exposure.
"""
import argparse
import csv
import hashlib
import io
import importlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid
import zipfile
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, quote
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener

TARGET, ATTACKER = "192.168.77.20", "192.168.77.10"
SENSORS = ("ssh-decoy-01", "web-decoy-01", "db-decoy-01", "file-decoy-01")
RULES = {"R01", "R02", "R03", "R04", "R07", "R08", "R09", "R11", "R12"}
CLASSES = {"sqli", "xss", "lfi", "rfi", "cmd_injection"}


class CheckFailure(ValueError):
    """Only program-authored, payload-free diagnostics may be shown."""


def require(condition, message="Unexpected result"):
    if not condition:
        raise CheckFailure(message)


class Report:
    def __init__(self, role, output):
        self.path = Path(output).resolve()
        self.path.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.data = {"role": role, "started_at": datetime.now(timezone.utc).isoformat(),
                     "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     "checks": [], "not_covered": ["browser rendering/reconnect", "durable restart/dedup",
                     "host egress capture", "Cowrie SFTP/forwarding channels", "every possible attack"]}

    def check(self, name, function):
        started = time.monotonic()
        try:
            result = function()
            require(result is not False)
            row = {"name": name, "status": "PASS"}
        except Exception as error:
            # Error messages/remote payloads can contain credentials. Keep type only.
            row = {"name": name, "status": "FAIL", "error_type": type(error).__name__}
            if isinstance(error, CheckFailure):
                row["detail"] = str(error)
        row["seconds"] = round(time.monotonic() - started, 2)
        self.data["checks"].append(row)
        print(row["status"], name, row.get("detail", row.get("error_type", "")), flush=True)
        self.save()
        return row["status"] == "PASS"

    def save(self):
        self.data["passed"] = sum(c["status"] == "PASS" for c in self.data["checks"])
        self.data["failed"] = sum(c["status"] == "FAIL" for c in self.data["checks"])
        path = self.path / "report.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(self.data, stream, indent=2)
            stream.write("\n")

    def finish(self):
        self.data["finished_at"] = datetime.now(timezone.utc).isoformat()
        self.save()
        print(f"REPORT: {self.path / 'report.json'}", flush=True)
        print(f"{self.data['passed']} PASS / {self.data['failed']} FAIL; see not_covered in report", flush=True)
        return 1 if self.data["failed"] else 0


def lab_guard(role, target=TARGET):
    require(target == TARGET, "Only 192.168.77.20 is allowed")
    require(sys.platform.startswith("linux"), "Run on the Kali lab VM")
    for family in ("-4", "-6"):
        result = subprocess.run(["ip", family, "route", "show", "default"], check=True,
                                capture_output=True, text=True, timeout=5)
        require(not result.stdout.strip(), "Disconnect NAT/default routes before testing")
    if shutil.which("nmcli"):
        wifi = subprocess.run(["nmcli", "radio", "wifi"], check=True, capture_output=True, text=True, timeout=5)
        require(wifi.stdout.strip() == "disabled", "Turn Wi-Fi off")
    if role == "attack":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((TARGET, 8080))  # route selection only; no packet sent
            require(sock.getsockname()[0] == ATTACKER, "Run attack on 192.168.77.10")
    else:
        result = subprocess.run(["ip", "-4", "-o", "addr", "show"], check=True,
                                capture_output=True, text=True, timeout=5)
        require(re.search(r"\b192\.168\.77\.20/24\b", result.stdout), "Run watch on Vedant .20")


def check_dependencies(role):
    if role != "attack":
        print("Watch dependencies: Python standard library only", flush=True)
        return
    missing = []
    # Optional offline bundle. Wheels are read directly, never installed.
    for name in ("pymysql-1.1.2-py3-none-any.whl", "impacket-0.13.1-py3-none-any.whl"):
        wheel = Path(__file__).resolve().parent / "wheels" / name
        if wheel.is_file():
            sys.path.insert(0, str(wheel))
    for package in ("pymysql", "impacket.smbconnection"):
        try:
            importlib.import_module(package)
        except ImportError:
            missing.append(package)
    missing.extend(name for name in ("ssh",) if not shutil.which(name))
    require(not missing, "Missing attacker dependencies: " + ", ".join(missing))
    print("Attack dependencies: PyMySQL, Impacket and OpenSSH found", flush=True)


class Web:
    def __init__(self, base, tag=""):
        self.base, self.tag = base, tag
        self.browser = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))

    def request(self, path, *, method="GET", data=None, headers=None):
        if self.tag:
            path += ("&" if "?" in path else "?") + urlencode({"dg_probe": self.tag})
        request = Request(self.base + path, data=data, headers=headers or {}, method=method)
        try:
            response = self.browser.open(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            body = response.read(65537)
            require(len(body) <= 65536, "Response exceeds test budget")
            return response.code, body, response.headers

    def expect(self, status, path, **kwargs):
        code, body, headers = self.request(path, **kwargs)
        require(code == status, f"HTTP {code}; expected {status}")
        return body, headers

    def form(self, path, values, status=200):
        return self.expect(status, path, method="POST", data=urlencode(values).encode(),
                           headers={"Content-Type": "application/x-www-form-urlencoded"})


def archive_credentials(data):
    expected = {"README.txt", "admin-secrets.txt", "customer_data.csv", "db_settings.txt", "share_accounts.csv"}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(len(archive.infolist()) == 5 and set(archive.namelist()) == expected)
        require(sum(e.file_size for e in archive.infolist()) <= 16384)
        require(all(stat.S_ISREG(e.external_attr >> 16) for e in archive.infolist()))
        require(archive.testzip() is None)
        database = dict(line.split("=", 1) for line in archive.read("db_settings.txt").decode().splitlines() if "=" in line)
        share = next(csv.DictReader(io.StringIO(archive.read("share_accounts.csv").decode())))
        require(database.get("HOST") == TARGET and database.get("USER") == "svc_reports")
        require(share.get("host") == TARGET and share.get("share") == "backups" and share.get("username") == "backup_ops")
        for value in (database.get("PASSWORD", ""), share.get("password", "")):
            require(value.startswith("DGLAB-") and len(value) <= 128)
        return database["PASSWORD"], share["password"]


def ssh_probe(directory, user, password, command, *, denied=False, exit_codes=(0,)):
    helper = directory / "askpass.sh"
    if not helper.exists():
        fd = os.open(helper, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, "w", newline="\n") as stream:
            stream.write('#!/bin/sh\nprintf "%s\\n" "$DG_LAB_SSH_PASSWORD"\n')
    environment = dict(os.environ, DG_LAB_SSH_PASSWORD=password,
                       SSH_ASKPASS=str(helper), SSH_ASKPASS_REQUIRE="force")
    args = ["ssh", "-F", "none", "-4", "-a", "-x", "-T", "-p", "2222",
            "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=4",
            "-o", "ConnectionAttempts=1", "-o", "NumberOfPasswordPrompts=1",
            "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
            "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={directory / 'known_hosts'}",
            f"{user}@{TARGET}", command]
    result = subprocess.run(args, env=environment, stdin=subprocess.DEVNULL,
                            start_new_session=True, capture_output=True, timeout=12)
    require(result.returncode in ((255,) if denied else exit_codes), f"SSH client exit {result.returncode}")
    if denied:
        require(b"permission denied" in result.stderr.lower(), "SSH failure was not authentication denial")
    return result.stdout


def multipart(data, mime="text/plain"):
    boundary = "DGLabAcceptanceBoundary"
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="report"; filename="report.txt"\r\n'
            f'Content-Type: {mime}\r\n\r\n').encode() + data + f"\r\n--{boundary}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def native_probes(report, database_password, smb_password, host=TARGET, mysql_port=3306, smb_port=445, failure_user=None):
    import pymysql
    from impacket.smbconnection import SMBConnection, SessionError
    def database(value, user="svc_reports"):
        return pymysql.connect(host=host, port=mysql_port, user=user, password=value,
                               connect_timeout=3, read_timeout=3, write_timeout=3)
    def bad_database():
        for index, user in enumerate([failure_user or "svc_reports"] * 5 + ["svc_reports"]):
            try:
                connection = database(f"DGLAB-Wrong-{index}", user)
            except pymysql.err.OperationalError as error:
                require(error.args[0] == 1045)
            else:
                connection.close()
                raise ValueError("Wrong credential accepted")
    report.check("MySQL: five guessing attempts + wrong planted-account password refused", bad_database)
    def good_database():
        connection = database(database_password)
        try:
            connection.ping(reconnect=False)
            with connection.cursor() as cursor:
                try:
                    cursor.execute("SELECT 1")
                except pymysql.err.OperationalError as error:
                    require(error.args[0] == 1142)
                else:
                    raise ValueError("Data query accepted")
        finally:
            connection.close()
    report.check("MySQL: planted proof accepted, ping/setup ACK, SELECT refused 1142", good_database)
    def smb():
        return SMBConnection("FILES-SRV-02", host, sess_port=smb_port, preferredDialect=0x202, timeout=3)
    def bad_smb():
        for user in [failure_user or "backup_ops"] * 5 + ["backup_ops"]:
            connection = smb()
            try:
                try:
                    connection.login(user, "DGLAB-Wrong-SMB", domain="WORKGROUP")
                except SessionError as error:
                    require(error.getErrorCode() == 0xc0000022)
                else:
                    raise ValueError("Wrong proof accepted")
            finally:
                connection.close()
    report.check("SMB: five guessing attempts + wrong planted-account proof refused", bad_smb)
    def smb_io():
        connection = smb()
        try:
            connection.login("backup_ops", smb_password, domain="WORKGROUP")
            output = io.BytesIO()
            connection.getFile("backups", "README.txt", output.write)
            require(b"synthetic" in output.getvalue().lower())
            data = b"Harmless DeceptionGraph acceptance upload; never executed.\n"
            connection.putFile("backups", "acceptance.txt", io.BytesIO(data).read)
            connection.logoff()
        finally:
            connection.close()
    report.check("SMB: planted proof, synthetic README read and harmless upload", smb_io)
    for name, operation in (
        ("IPC$ share denied", lambda c: c.connectTree("IPC$")),
        ("path traversal denied", lambda c: c.putFile("backups", "../outside.txt", io.BytesIO(b"inert").read)),
        ("fixed asset overwrite denied", lambda c: c.putFile("backups", "README.txt", io.BytesIO(b"inert").read)),
        ("oversized upload refused", lambda c: c.putFile("backups", "large.txt", io.BytesIO(b"x" * 20000).read)),
    ):
        def denied(operation=operation):
            connection = smb()
            try:
                connection.login("backup_ops", smb_password, domain="WORKGROUP")
                try:
                    operation(connection)
                except SessionError as error:
                    require(error.getErrorCode() in {0xc0000022, 0xc000000d})
                else:
                    raise ValueError("Restricted operation accepted")
            finally:
                connection.close()
        report.check("SMB: " + name, denied)


def attack(report, response_seconds):
    import pymysql  # fail before sending traffic if dependencies are absent
    from impacket.smbconnection import SMBConnection
    require(shutil.which("ssh"), "OpenSSH client is required")
    tag = "dgcheck_" + uuid.uuid4().hex[:12]
    failure_user = "probe_" + tag
    report.data.update(probe_id=tag, target=TARGET, expected_source=ATTACKER)
    web = Web(f"http://{TARGET}:8080", tag)
    for index in range(5):
        report.check(f"SSH: wrong password {index + 1}/5 refused", lambda i=index:
                     ssh_probe(report.path, failure_user, f"DGLAB-Wrong-SSH-{i}", "pwd", denied=True))
    report.check("SSH: discovery ls", lambda: ssh_probe(report.path, "dg_demo", "DemoPass-2026", "ls -la"))
    def note():
        data = ssh_probe(report.path, "dg_demo", "DemoPass-2026", "cat /home/dg_demo/notes.txt")
        require(b"svc_portal" in data and b"DGLAB-Portal-4471" in data)
    report.check("SSH: emulated bait note output", note)
    def network():
        data = ssh_probe(report.path, "dg_demo", "DemoPass-2026", "curl https://example.invalid/dg-acceptance", exit_codes=(0, 1))
        require(b"Network access is unavailable" in data)
    report.check("SSH: canned network-tool denial", network)
    report.check("Web: anonymous dashboard denied", lambda: web.expect(401, "/dashboard"))
    report.check("Web: anonymous export denied", lambda: web.expect(401, "/download?file=customer_data.csv"))
    report.check("Web: wrong login refused", lambda: web.form("/login", {"username": "svc_portal", "password": "DGLAB-Wrong-Web"}, 401))
    report.check("Web: planted portal login", lambda: web.form("/login", {"username": "svc_portal", "password": "DGLAB-Portal-4471"}))
    report.check("Web: authenticated dashboard", lambda: web.expect(200, "/dashboard"))
    report.check("Web: authenticated synthetic CSV", lambda: web.expect(200, "/download?file=customer_data.csv"))
    payloads = {"sqli": "1' OR 1=1--", "xss": "<script>alert(1)</script>",
                "lfi": "../../etc/passwd", "rfi": "https://example.invalid/inert.txt",
                "cmd_injection": "; id"}
    for kind, payload in payloads.items():
        expected = 500 if kind == "sqli" else 200
        report.check(f"Web: {kind} GET observation", lambda p=payload, s=expected, k=kind:
                     web.expect(s, "/search?" + urlencode({"include" if k == "rfi" else "q": p})))
        report.check(f"Web: {kind} JSON-body observation", lambda p=payload, s=expected:
                     web.expect(s, "/search", method="POST", data=json.dumps({"q": p}).encode(), headers={"Content-Type": "application/json"}))
    report.check("Web: SQLi form-body observation", lambda: web.form("/search", {"q": payloads["sqli"]}, 500))
    report.check("Web: double-encoded SQLi observation", lambda:
                 web.expect(500, "/search?q=" + quote(quote(payloads["sqli"], safe=""), safe="")))
    report.check("Web: benign search", lambda: web.expect(200, "/search?q=quarterly+report"))
    def probing():
        for path in ("/admin", "/administrator", "/.git/HEAD", "/.git/config", "/phpmyadmin", "/wp-admin"):
            require(web.request(path)[0] in {200, 401, 404})
        for index in range(10):
            web.expect(404, f"/dg-missing-{tag}-{index}")
    report.check("Web: bounded hidden-path and 404 probing", probing)
    report.check("Web: public SSH backup bait", lambda: web.expect(200, "/.env"))
    report.check("SSH: reuse planted backup credential", lambda:
                 ssh_probe(report.path, "backup", "DGLAB-Bkp-2210", "pwd"))
    credentials = []
    def zip_probe():
        first, headers = web.expect(200, "/backup/backup.zip")
        require(headers.get_content_type() == "application/zip")
        credentials.extend(archive_credentials(first))
        second, _ = web.expect(200, "/backup/backup.zip")
        require(first == second)
        head, _ = web.expect(200, "/backup/backup.zip", method="HEAD")
        require(not head)
    report.check("ZIP: five inert entries, credential plants, repeat GET and HEAD", zip_probe)
    for name, data, mime, expected in (
        ("text discarded", b"Harmless acceptance report.", "text/plain", 200),
        ("binary type refused", b"inert", "application/octet-stream", 415),
        ("NUL text refused", b"inert\x00text", "text/plain", 415),
        ("over 8 KiB refused", b"x" * 9000, "text/plain", 413),
    ):
        body, headers = multipart(data, mime)
        report.check("Web upload: " + name, lambda b=body, h=headers, s=expected:
                     web.expect(s, "/upload", method="POST", data=b, headers=h))
    report.check("Web: malformed JSON refused", lambda: web.expect(400, "/search", method="POST", data=b"{", headers={"Content-Type": "application/json"}))
    report.check("Web: logout", lambda: web.form("/logout", {}))
    report.check("Web: export denied after logout", lambda: web.expect(401, "/download?file=customer_data.csv"))
    if len(credentials) == 2:
        native_probes(report, *credentials, failure_user=failure_user)
    else:
        report.check("MySQL/SMB: require validated ZIP credentials", lambda: False)
    report.check("Traffic sequence completion marker", lambda: web.expect(200, "/login?dg_phase=complete"))
    if response_seconds:
        print("Waiting for Vedant's optional response test; harmless GET every 2 seconds.", flush=True)
        seen_denial, restored = False, False
        deadline = time.monotonic() + response_seconds
        while time.monotonic() < deadline:
            code = web.request("/login")[0]
            if code == 403:
                seen_denial = True
            elif seen_denial and code == 200:
                restored = True
                break
            time.sleep(2)
        report.check("Response: attacker observed 403 then restored 200", lambda: seen_denial and restored)
    return report.finish()


class Api:
    def __init__(self, base="http://127.0.0.1:8000"):
        self.base, self.browser = base, build_opener(ProxyHandler({}))

    def call(self, route, body=None):
        request = Request(self.base + route, data=None if body is None else json.dumps(body).encode(),
                          headers={} if body is None else {"Content-Type": "application/json"})
        try:
            with self.browser.open(request, timeout=5) as response:
                data = response.read(4 * 1024 * 1024 + 1)
                require(len(data) <= 4 * 1024 * 1024)
                return json.loads(data)
        except HTTPError as error:
            raise CheckFailure(f"SOC returned HTTP {error.code}") from None

    def events(self, run, cursor):
        return self.call("/api/events?" + urlencode({"lab_run_id": run, "capture_mode": "live", "since_seq": cursor, "limit": 1000}))


def evidence_state(events, findings, links):
    ids = {e["event_id"] for e in events}
    rows = [f for f in findings if ids.intersection(f["evidence_event_ids"])]
    observed = {f["rule_id"] for f in rows}
    classes = {c for f in rows if f["rule_id"] == "R07" for c in f.get("web_attack_class", [])}
    json_ids = {e["event_id"] for e in events if e["attributes"].get("input_features", {}).get("source") == "json"}
    query_ids = {e["event_id"] for e in events if e["attributes"].get("method") == "GET"}
    def detected(kind, ids):
        return any(f["rule_id"] == "R07" and kind in f.get("web_attack_class", []) and ids.intersection(f["evidence_event_ids"]) for f in rows)
    benign_ids = {e["event_id"] for e in events if "q=quarterly+report" in e["attributes"].get("query_redacted", "")}
    def has(sensor, kind, predicate=lambda a: True):
        return any(e["sensor_id"] == sensor and e["event_type"] == kind and predicate(e["attributes"]) for e in events)
    proof = lambda a: a.get("credential", {}).get("proof_check") == "matched_honeytoken"
    valid_links = [l for l in links if l["from_event_id"] in ids and l["to_event_id"] in ids]
    return {"all four actual sources": {e["sensor_id"] for e in events} == set(SENSORS),
        "traffic sequence completion marker": has("web-decoy-01", "http_request", lambda a: "dg_phase=complete" in a.get("query_redacted", "")),
        **{f"rule {rule}": rule in observed for rule in sorted(RULES)},
        **{f"web class {kind}": kind in classes for kind in sorted(CLASSES)},
        **{f"JSON class {kind}": detected(kind, json_ids) for kind in sorted(CLASSES)},
        **{f"GET class {kind}": detected(kind, query_ids) for kind in sorted(CLASSES)},
        "benign search has no R07": bool(benign_ids) and not any(f["rule_id"] == "R07" and benign_ids.intersection(f["evidence_event_ids"]) for f in rows),
        "MySQL matched proof": has("db-decoy-01", "auth_success", proof),
        "SMB matched proof": has("file-decoy-01", "auth_success", proof),
        "MySQL query not executed": has("db-decoy-01", "db_request", lambda a: a.get("db", {}).get("execution") == "not_supported" and a.get("db", {}).get("error_code") == 1142),
        "SMB inert upload result": has("file-decoy-01", "file_operation", lambda a: a.get("file", {}).get("storage") == "quarantined_inert"),
        "ZIP transfer completion unknown": has("web-decoy-01", "bait_served", lambda a: a.get("asset_id") == "web:/backup/backup.zip" and a.get("transfer", {}).get("completion") == "unknown"),
        "web upload discarded": has("web-decoy-01", "http_request", lambda a: a.get("upload_outcome") == "accepted_discarded"),
        **{f"{source} body indicators collected": has("web-decoy-01", "http_request", lambda a, s=source: a.get("input_features", {}).get("source") == s and bool(a.get("input_features", {}).get("indicators"))) for source in ("json", "form")},
        "network command denied": has("ssh-decoy-01", "command_input", lambda a: a.get("network_attempt_outcome") == "denied" and a.get("real_execution") is False),
        **{f"ZIP causal link to {sensor}": any(l["to_sensor"] == sensor and l.get("attribution") in {"unique", "ambiguous"} for l in valid_links) for sensor in ("db-decoy-01", "file-decoy-01")},
        **{f"R11 on {sensor}": any(f["rule_id"] == "R11" and any(e["event_id"] in f["evidence_event_ids"] and e["sensor_id"] == sensor for e in events) for f in rows) for sensor in ("db-decoy-01", "file-decoy-01")}}


def findings_for(api, events):
    findings = {}
    owners = {e["incident_id"] for e in events}
    runs, peers = {e["lab_run_id"] for e in events}, {e["src_ip"] for e in events}
    # Credential-attempt cases own rule findings while session cases own rows.
    summaries = api.call("/api/incidents")["items"]
    require(len(summaries) <= 1000, "Case lookup exceeds acceptance budget")
    owners.update(i["incident_id"] for i in summaries if i["lab_run_id"] in runs and i["src_ip"] in peers
                  and i.get("case_kind") == "credential_attempts")
    for incident in owners:
        for finding in api.call("/api/incidents/" + incident)["findings"]:
            findings[finding["finding_id"]] = finding
    return list(findings.values())


def response_test(api, report, events, links):
    ids = {e["event_id"] for e in events}
    candidates = [l for l in links if l["from_event_id"] in ids and l["to_event_id"] in ids
                  and l["status"] == "open" and l["kind"] == "strong_candidate"]
    require(candidates, "No fresh causal link for manual review")
    case = next(e["incident_id"] for e in reversed(events) if e["sensor_id"] == "web-decoy-01" and e["event_type"] == "bait_served")
    preview = api.call("/api/response/preview", {"incident_id": case, "ttl_seconds": 120})
    require(preview["target_ip"] == ATTACKER and preview["scope"] == "web-decoy-01 only")
    print("Preview: block 192.168.77.10 on web-decoy-01 only for 120 seconds.", flush=True)
    print("Also confirm one fresh causal link as an analyst test, then reject it during cleanup.", flush=True)
    require(input("Type APPLY within 60 seconds to authorize these test actions: ").strip() == "APPLY", "Actions not authorized")
    # Never touch an existing action, including one that could outlive this test.
    require(not any(a["target_ip"] == ATTACKER and a["status"] in {"applied", "verified", "reconciliation_required"}
                    for a in api.call("/api/response/actions")["items"]), "Existing response action present")
    link, action_id = candidates[0], None
    reason = "Physical acceptance " + uuid.uuid4().hex + "; analyst authorized; revoke follows."
    confirmed = False
    try:
        api.call(f"/api/links/{link['link_id']}/decision", {"decision": "confirm", "rationale": "Analyst authorized bounded physical-lab acceptance; identity not established."})
        confirmed = True
        details = [api.call("/api/incidents/" + i["incident_id"]) for i in api.call("/api/incidents")["items"] if i.get("case_kind") == "investigation"]
        report.check("Analyst confirmation: backend investigation and R05", lambda:
                     any(any(f["rule_id"] == "R05" and set(f["evidence_event_ids"]) == {link["from_event_id"], link["to_event_id"]} for f in d["findings"]) for d in details))
        report.check("Analyst confirmation: R09 counted in an investigation", lambda:
                     any(any(s["rule_id"] == "R09" and s["counted"] for s in d["score_breakdown"]) for d in details))
        action = api.call("/api/response/apply", {"preview_id": preview["preview_id"], "reason": reason, "confirm": True})
        action_id = action["action_id"]
        report.data["response_action_id"] = action_id
        report.check("Response: apply returned pending, not claimed verified", lambda: action["status"] == "applied")
        deadline, verified = time.monotonic() + 45, None
        while time.monotonic() < deadline:
            verified = next(a for a in api.call("/api/response/actions")["items"] if a["action_id"] == action_id)
            if verified["status"] == "verified":
                break
            time.sleep(1)
        report.check("Response: collected denial verified by backend", lambda:
                     verified["status"] == "verified" and bool(verified.get("verified_by_event_id")))
        report.data["verified_by_event_id"] = verified.get("verified_by_event_id")
    finally:
        try:
            if action_id is None:
                # An apply can commit even when its HTTP response is lost.
                recovered = [a for a in api.call("/api/response/actions")["items"]
                             if a.get("reason") == reason and a["target_ip"] == ATTACKER]
                if len(recovered) == 1:
                    action_id = recovered[0]["action_id"]
            if action_id:
                revoked_at = datetime.now(timezone.utc).isoformat()
                revoked = api.call(f"/api/response/{action_id}/revoke", {})
                report.check("Response: revoke acknowledged", lambda: revoked["status"] == "revoked")
                deadline, restored = time.monotonic() + 20, False
                while time.monotonic() < deadline:
                    newer = api.events(events[0]["lab_run_id"], max(e["seq"] for e in events))["items"]
                    restored = any(e["src_ip"] == ATTACKER and e["sensor_id"] == "web-decoy-01"
                                   and datetime.fromisoformat(e["ingested_at"].replace("Z", "+00:00")) >= datetime.fromisoformat(revoked_at)
                                   and e["attributes"].get("status_code") == 200 for e in newer)
                    if restored:
                        break
                    time.sleep(1)
                report.check("Response: restored 200 collected from attacker", lambda: restored)
        finally:
            if confirmed:
                api.call(f"/api/links/{link['link_id']}/decision", {"decision": "reject", "rationale": "Acceptance cleanup; remove test confirmation and its investigation."})
                report.check("Analyst confirmation: test link reversed", lambda: True)


def watch(report, env_file, timeout, actions):
    settings = dict(line.split("=", 1) for line in Path(env_file).read_text().splitlines() if line and not line.startswith("#") and "=" in line)
    run = settings["LAB_RUN_ID"]
    require(settings.get("LAB_HOST_IP") == TARGET and settings.get("ATTACKER_IPS") == ATTACKER)
    api, cursor = Api(), 0
    for _ in range(100):
        page = api.events(run, cursor)
        cursor = page["next_seq"]
        if len(page["items"]) < 1000:
            break
    else:
        raise ValueError("Baseline exceeds bounded page budget")
    baseline = api.call("/api/health")
    report.data.update(lab_run_id=run, baseline_seq=cursor, expected_source=ATTACKER,
                       physical_evidence="network peers reported by actual sensors; verify preflight separately")
    print(f"READY. Run attack now on .10. Watching NEW records only, after seq {cursor}.", flush=True)
    deadline, events, state = time.monotonic() + timeout, [], {}
    last_progress = None
    while time.monotonic() < deadline:
        page = api.events(run, cursor)
        cursor = page["next_seq"]
        events.extend(page["items"])
        require(len(events) <= 5000, "Acceptance event budget exceeded")
        relevant = [e for e in events if e["src_ip"] == ATTACKER]
        findings = findings_for(api, relevant)
        links = api.call("/api/links")["items"]
        state = evidence_state(relevant, findings, links)
        progress = (len(events), sum(state.values()))
        if progress != last_progress:
            print(f"COLLECTED {progress[0]} new records; {progress[1]}/{len(state)} evidence checks satisfied", flush=True)
            last_progress = progress
        if state and all(state.values()):
            break
        time.sleep(2)
    relevant = [e for e in events if e["src_ip"] == ATTACKER]
    for name, value in state.items():
        report.check("SOC: " + name, lambda v=value: v)
    report.check("SOC: no unexpected source peer in fresh records", lambda: bool(events) and len(relevant) == len(events))
    report.check("SOC: no plaintext lab credentials in fresh events", lambda: "DGLAB-" not in json.dumps(events))
    probe_ids = {match for e in relevant for match in re.findall(r"dg_probe=(dgcheck_[0-9a-f]{12})", e["attributes"].get("query_redacted", ""))}
    report.data["probe_ids"] = sorted(probe_ids)
    report.check("SOC: exactly one tagged probe sequence", lambda: len(probe_ids) == 1)
    health = api.call("/api/health")
    for sensor in SENSORS:
        row = health.get("sensor_health", {}).get(sensor, {})
        before = baseline.get("sensor_health", {}).get(sensor, {})
        report.check("Collector: " + sensor, lambda r=row:
                     r.get("collection") == "ok" and r.get("process_state") == "running" and r.get("last_read_at") is not None and r.get("backlog_records") == 0)
        for counter in ("rejected", "quarantined"):
            report.check(f"Collector: {sensor} no new {counter}", lambda r=row, b=before, c=counter:
                         r.get("ingest", {}).get(c) == (b.get("ingest") or {}).get(c, 0))
    require(relevant, "No fresh .10 records collected")
    case = next(e["incident_id"] for e in relevant if e["sensor_id"] == "web-decoy-01")
    report.check("SOC: incident export available", lambda: bool(api.call("/api/incidents/" + case + "/export").get("events")))
    report.data.update(event_count=len(events), event_ids=[e["event_id"] for e in relevant],
                       source_counts={s: sum(e["sensor_id"] == s for e in relevant) for s in SENSORS})
    if actions and state and all(state.values()) and not report.data.get("failed"):
        report.check("Operator-authorized analyst/response flow", lambda: response_test(api, report, relevant, links))
    else:
        report.data["not_covered"].append("analyst confirmation and response" if not actions else "actions withheld because evidence checks failed")
    return report.finish()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("attack", "watch"))
    parser.add_argument("--target", default=TARGET)
    parser.add_argument("--output")
    parser.add_argument("--env-file", default="deployment/lab.env")
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--response-window", type=int, default=0, help="attacker polls for denial/recovery for this many seconds")
    parser.add_argument("--actions", action="store_true", help="watch: offer a manual APPLY prompt for confirmation + 120s web block/revoke")
    parser.add_argument("--check-deps", action="store_true", help="check imports/tools only; no network traffic")
    args = parser.parse_args(argv)
    if args.target != TARGET or not 30 <= args.timeout <= 600 or not 0 <= args.response_window <= 300:
        parser.error("Only isolated lab target 192.168.77.20 and bounded timeouts are allowed")
    try:
        check_dependencies(args.role)
        if args.check_deps:
            return 0
        lab_guard(args.role, args.target)
    except Exception as error:
        detail = str(error) if isinstance(error, CheckFailure) else type(error).__name__
        print("STOP: " + detail + ". Check VM, dependencies and isolation.", file=sys.stderr)
        return 2
    output = args.output or ("dg-acceptance-" + args.role + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    report = Report(args.role, output)
    try:
        return attack(report, args.response_window) if args.role == "attack" else watch(report, args.env_file, args.timeout, args.actions)
    except KeyboardInterrupt:
        report.check("Run interrupted", lambda: False)
    except Exception as error:
        report.check("Run stopped: " + type(error).__name__, lambda: False)
    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())

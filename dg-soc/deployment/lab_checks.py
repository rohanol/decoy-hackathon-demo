#!/usr/bin/env python3
"""Read-only lab gates. Never print raw honeypot records (they contain passwords)."""
import collections
from datetime import datetime, timedelta, timezone
import json
import ipaddress
import os
from pathlib import Path
import platform
import subprocess
import sys


def output(args):
    return subprocess.check_output(args, text=True).strip()


def host_errors():
    errors = []
    if platform.system() != "Linux":
        return ["Use native Linux Docker Engine or a Linux VM bridged to the lab NIC"]
    release = platform.release().lower()
    docker_os = output(["docker", "info", "--format", "{{.OperatingSystem}}"])
    if "microsoft" in release or "wsl" in release or "docker desktop" in docker_os.lower():
        errors.append("Docker Desktop/WSL is unsupported for this lab: verify on native Linux Docker Engine")
    for family in ("-4", "-6"):
        if output(["ip", family, "route", "show", "default"]):
            errors.append(f"{family} default route present: disconnect Internet during runs")
    return errors


def profile_errors():
    mounts = json.loads(output(["docker", "inspect", "--format", "{{json .Mounts}}", "dg-cowrie"]))
    required = {"/cowrie/cowrie-git/src/cowrie/commands/__init__.py",
                "/cowrie/cowrie-git/src/cowrie/commands/lab_network.py",
                "/cowrie/cowrie-git/custom/fs.pickle"}
    readonly = {mount["Destination"] for mount in mounts if not mount.get("RW", True)}
    return [f"Cowrie lab profile missing read-only mount: {path}" for path in sorted(required - readonly)]


def source_errors(paths, expected, now=None):
    now = now or datetime.now(timezone.utc)
    errors = []
    for name, path in paths.items():
        counts = collections.Counter()
        try:
            # Stream only; never echo or persist the password-bearing input.
            with Path(path).open() as stream:
                for line in stream:
                    try:
                        event = json.loads(line)
                        if event.get("capture_mode") not in (None, "live"):
                            continue
                        if name == "web" and event.get("capture_mode") != "live":
                            continue
                        timestamp = event.get("timestamp") or event.get("occurred_at")
                        at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                        if at.tzinfo is not None and now - timedelta(minutes=5) <= at <= now + timedelta(seconds=10):
                            ip = event.get("src_ip")
                            if isinstance(ip, str) and ip:
                                try:
                                    ip = str(ipaddress.IPv4Address(ip))
                                except ipaddress.AddressValueError:
                                    ip = "<invalid-ip>"
                                counts[ip] += 1
                    except (ValueError, TypeError, AttributeError):
                        continue
        except OSError:
            errors.append(f"{name}: log unavailable; make the documented manual lab probe first")
            continue
        if not counts:
            errors.append(f"{name}: no fresh source-IP evidence within five minutes")
        unexpected = set(counts) - expected
        if unexpected:
            errors.append(f"{name}: unexpected peer IPs {sorted(unexpected)}; do not relabel gateway IPs")
        missing = expected - set(counts)
        if missing:
            errors.append(f"{name}: missing expected peer IPs {sorted(missing)}")
        if counts and not unexpected and not missing:
            print(f"PASS  {name}: fresh source IPs {sorted(counts)}")
    return errors


def main(argv):
    if argv == ["host"]:
        errors = host_errors()
    elif argv == ["profile"]:
        errors = profile_errors()
    elif len(argv) == 3 and argv[0] == "source":
        expected = set(os.environ.get("ATTACKER_IPS", "192.168.77.10").replace(",", " ").split())
        if not expected:
            raise ValueError("ATTACKER_IPS must not be empty")
        errors = source_errors({"Cowrie": argv[1], "web": argv[2]}, expected)
    else:
        raise ValueError("Usage: lab_checks.py host | source COWRIE_LOG WEB_LOG")
    for error in errors:
        print("FAIL ", error)
    return int(bool(errors))


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"FAIL  lab readiness could not be checked: {error}", file=sys.stderr)
        raise SystemExit(1)

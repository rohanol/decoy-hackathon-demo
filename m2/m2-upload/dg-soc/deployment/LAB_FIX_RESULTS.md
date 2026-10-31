# Cowrie lab fixes — 31 October

Prepared against the exact reported Cowrie digest ending `1050d`. These are
cloud/offline verification results, separate from Rohan's physical-lab report.

| Reported issue | Change | Evidence / remaining check |
| --- | --- | --- |
| Windows Docker gateway appears as peer | Preflight rejects Desktop/WSL and requires fresh expected IPs from both decoys | Mocked Desktop, stale/missing evidence and gateway-IP tests pass. Actual Kali → Linux check still required. No peer IP rewriting. |
| Image has no shell | Pin/build use stopped `docker create` + `docker cp` and verified packaged paths | Both scripts completed against the exact image; all configured options validated. |
| Empty duplicate demo home | Custom pickle includes exactly one persistent demo passwd entry | Actual image's `Passwd` resolves the configured demo home and UID. |
| Empty note text | Embed note bytes in the pickle, not just its size; configure/mount the custom pickle | Actual image's filesystem lists the note and reads bytes identical to the bait file. |
| Emulated download commands make real requests | A read-only small lab command registry routes network tools to canned failure handlers | Actual image's dispatch map uses the canned handlers, with DNS/connect traps, in a network-disabled read-only container. Offline host checks cover IPv4 and IPv6 default routes. |

Commands executed:

```bash
bash deployment/pin_cowrie.sh
bash decoys/ssh/build_fs.sh
python decoys/ssh/check_image.py
python -m pytest decoys/ssh/test_patch_fs.py deployment/test_lab_checks.py tests/e2e -q
```

The combined M4 and new regression suite passed **64 tests**. The offline image
check passed using real Cowrie code; it opens no SSH service and sends no attack
traffic. Generated image pickles remain ignored and are not committed. Active
fixes under `dg-soc/` are mirrored into the M2 upload where relevant.

The deliberately smaller command profile retains the demo's emulated shell,
whoami/ls/find/cat and basic filesystem commands. Other nonessential applets may
be unavailable. Do not restore the full stock registry to improve realism: that
would re-enable real download behavior. Review any additions against the pinned
image first. Keep the physical host offline even with this command profile.

Remaining: use [LINUX_LAB_CHECKLIST.md](LINUX_LAB_CHECKLIST.md), make manual SSH
and web probes from Kali, confirm real `192.168.77.10` in both logs, then run the
complete demo including block/undo/expiry. No new real Cowrie sample is supplied:
the referenced laptop-only sample was not available and must be freshly redacted
by the team before sharing.

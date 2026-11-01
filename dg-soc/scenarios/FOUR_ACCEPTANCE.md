# Physical four-honeypot acceptance

`four_acceptance.py` is a standalone Python file: copy the same file to both
Kali VMs. The attacker sends bounded real protocol traffic; Vedant's watcher
reads the existing SOC on loopback. It never exposes the backend to the LAN,
injects events, downloads dependencies or substitutes synthetic events for a
physical observation. Keep unrelated lab traffic quiet during the run.

## Preparation

The watcher needs only Python's standard library. The attacker needs system
OpenSSH `ssh`, PyMySQL (verified 1.1.2) and Impacket (verified 0.13.1).
The downloadable tester bundle includes those two pure-Python wheels under
`wheels/`; the script can read them directly without installation or internet.
Impacket's supporting libraries must already be installed (normally provided
by Kali's python3-impacket package). Check before starting the watcher.
Check without sending traffic, even during the preparation phase:

```bash
python3 four_acceptance.py attack --check-deps
```

If dependencies are missing, stop Vedant's decoys before reconnecting temporary
internet for installation. Kali packages are openssh-client,
python3-pymysql and python3-impacket. Return both machines to isolation before
testing. The runner refuses a non-Linux host, default IPv4/IPv6 routes, enabled
Wi-Fi, a non-.10 attacker source, a non-.20 watcher and any other target.

SSH uses a test-specific known_hosts file under its private report directory.
The first connection records that isolated lab endpoint's key; subsequent
connections in the same run refuse a changed key. This is test-local trust on
first use, not independent host identity verification. Password prompts use
[OpenSSH's documented SSH_ASKPASS_REQUIRE=force mechanism](https://man.openbsd.org/ssh#SSH_ASKPASS_REQUIRE) and a private helper
that contains no credential value. No sshpass package is required. User SSH
configuration, proxies and forwarding settings are bypassed for this test.
Raw command responses,
passwords, NTLM proofs and ZIP credential values are not printed or saved.

## Run

Start the existing four-service lab normally. Copy the standalone script into
~/Downloads on both VMs (or use this repo's scenarios/four_acceptance.py).

On **Vedant .20**, start the watcher first:

```bash
cd "$(cat "$HOME/DeceptionGraphLab/current-prototype-path.txt")"
python3 ~/Downloads/four_acceptance.py watch --timeout 300 --actions
```

Wait for `READY. Run attack now`. It snapshots a sequence watermark, then
accepts only later live records from the configured run. Past feed contents
cannot make this check pass. Credential-attempt findings are looked up in
their actual derived cases as well as session cases. Unique test usernames
avoid reusing an old guessing window on repeated acceptance runs.

On **attacker .10**:

```bash
python3 ~/Downloads/four_acceptance.py attack --response-window 180
```

When the watcher has observed all required evidence, it offers a preview:
type **APPLY** on Vedant within 60 seconds to authorize one test link
confirmation and a 120-second web-only block. The attacker polls once every
two seconds, observes 403 and then restored 200. The watcher waits for actual
collected denial/backend verification, revokes its own action and rejects its
test link during cleanup. The audit trail remains. It does not modify an
existing block or confirm a historical link.

Without these optional actions, omit `--actions` and omit the attacker's
`--response-window`; the report explicitly leaves those features untested.
If evidence fails, actions are withheld. On interruption, cleanup runs best
effort; a hard kill, machine loss or unavailable backend can prevent it. The
120-second policy expiry is the fallback. Do not manually edit the blocklist.

Both processes save a private **dg-acceptance-ROLE-TIMESTAMP/report.json**,
print PASS/FAIL lines and exit nonzero on failure. Both reports must pass;
client success alone is not proof that the adapter/backend collected it.

Finally on Vedant, within five minutes of the protocol probes:

```bash
source .venv/bin/activate
bash deployment/preflight_four.sh
```

## Coverage

The attacker makes **47 checks**, plus an optional response observation:

- Five distinct SSH password guesses for a unique synthetic account; valid
  login, ls, actual emulated note output, canned network-tool refusal and
  reuse of the web-planted backup credential.
- Web anonymous/authenticated boundaries, wrong/correct login, CSV serving,
  logout/revocation of access; SQLi, XSS, LFI, RFI and command-shaped requests
  through URL and JSON bodies, SQLi form/double encoding, benign search,
  six hidden paths and ten unique 404s.
- Text upload discard, bad type/NUL/size refusal and malformed JSON refusal.
- ZIP response type, five regular bounded entries, planted destinations,
  deterministic repeat servings and bodyless HEAD. Contents stay in memory.
- MySQL repeated guesses and invalid known-account proof, valid proof,
  client setup/ping and query refusal with error 1142.
- SMB repeated guesses and invalid known-account proof, valid NTLMv2,
  synthetic read, one harmless upload, IPC$/traversal/fixed-asset overwrite
  and oversized-upload refusal. No real malware, extraction or execution.

The watcher checks all four sources with actual .10 peers, R01/R02/R03/R04/
R07/R08/R09/R11/R12 with fresh cited events, all five web classes, R11 on
both native services, JSON/form indicators, native proof and inert-storage
facts, ZIP-to-MySQL/SMB links, unknown transfer completion, no plaintext lab
secrets, per-source collector health and no new rejected/quarantined counts,
and incident export. Optional authorized actions check R05/R09 scoring in a
backend investigation and preview/apply/verification/revoke/restored access.

This is bounded acceptance of implemented behaviors, not every possible
attack or a proof of immunity. It does not replace browser rendering,
reconnect, restart/dedup, TTL-expiry, quarantine-cap stress, packet fuzzing,
egress packet capture or Cowrie SFTP/forwarding checks. Those remain separate
checks; the JSON report lists material exclusions. Alerts describe attempts
and emulated results, never a real compromise or malware verdict.

## Developer verification

`python -m pytest tests/e2e/test_four_acceptance.py -q` runs the actual web,
MySQL and SMB clients against local producers and passes their records through
the adapter/backend. SSH is explicitly synthetic in this test. It also checks
manual refusal, normal cleanup, a lost apply response and diagnostic privacy.
These developer checks do not claim physical Kali success.

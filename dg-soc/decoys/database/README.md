# MySQL authentication decoy — M4

Source identity `db-decoy-01`; event schema **1.2** from M3 contract `eb2a94e`
(PR #19), backend runtime `6446ca1` (PR #20). This is an original bounded
standard-library protocol emulator, not a database engine or an imported
qeeqbox service. There are no runtime Python dependencies beyond Python 3.11+.

Protocol references: [MySQL native authentication](https://dev.mysql.com/doc/dev/mysql-server/8.4.11/page_protocol_connection_phase_authentication_methods_native_password_authentication.html)
and [HandshakeV10](https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_connection_phase_packets_protocol_handshake_v10.html).

## Supported behavior

- MySQL protocol-41 handshake with a fresh 20-byte challenge per connection;
  `mysql_native_password` only. Verified with **PyMySQL 1.1.2** on loopback.
- Account `svc_reports` uses `tok_db_01`, planted in the web ZIP's
  `db_settings.txt`. The database holds only SHA1(SHA1(password)), a protocol
  verifier; it does not store the planted value. It reconstructs the first-stage
  digest from the proof and compares its SHA-1 to the verifier in constant time.
- Successful verification produces `auth_success` / `emulated_success` and
  `credential.proof_check=matched_honeytoken`. It does not create a real database.
- Exact client-bootstrap messages `SET NAMES utf8mb4`, `SET NAMES utf8`,
  `SET NAMES latin1`, `SET AUTOCOMMIT = 0/1`, and COM_PING get canned ACKs.
  These are no-ops. Data queries, prepared statements and other commands are
  refused with error 1142. No statement is evaluated.
- TLS, `caching_sha2_password`, cleartext-password authentication and old
  pre-4.1 authentication are unsupported; no cleartext auth switch is requested.
  Do not assume compatibility with every modern MySQL CLI/plugin combination.

## Run and deployment

From `dg-soc`, after the network-isolation check:

```bash
LAB_RUN_ID=run-your-current-lab CAPTURE_MODE=live \
python -m decoys.database.server --host 192.168.77.20 --port 3306 \
  --log deployment/state/db-log/db.json
```

For disposable developer checks use loopback and a spare port. Host CLI binds
only loopback or the exact lab IP by default. No default-route changes occur.

Environment: `LAB_RUN_ID`, `CAPTURE_MODE` (`live`/`replay`), `DB_BIND_IP`,
`DB_PORT`, `DB_LOG_PATH`. CLI host/port/log override the latter settings.

Docker build context is `decoys/database/`. The image runs uid/gid 1000 and
binds `0.0.0.0:3306` **inside the container**, explicitly enabled with its
`DB_CONTAINER_BIND=1`. The four-service Compose override publishes only `192.168.77.20:3306:3306`, provisions
the writable `/logs` mount for uid 1000, use read-only root, cap-drop ALL,
no-new-privileges and an isolated network, and verify no unintended egress.
No privileged mode, host filesystem mount or Docker socket is needed.

There is no HTTP readiness route. The process prints one fixed ready message
after the listener binds. A TCP readiness connection generates a connection
event, not proof of a login or collector health. The integrated adapter ships
the native records and per-sensor collector heartbeats. Native container/network
acceptance is still required on Kali.

## Metadata, privacy and bounds

One JSONL record per event, each with a stable generated source_record_id:
`connection_open`, `auth_success`/`auth_failure`, `db_request`, `connection_close`.
They include actual TCP peer IPv4/port, a generated connection reference,
run/mode and `attributes.protocol=mysql`.

Credential events contain only scheme/check/version, a bounded account label,
and a token id when verified. Known lab/public account labels remain visible;
other account names become keyed, process-local `redacted_<reference>` values.
The same unknown name keeps one reference during the process lifetime;
different names do not collapse into one R11 account. References change after
restart. SQL, schema names, challenges, proofs, arbitrary client attributes,
passwords and exception strings never enter native logs. There is no raw packet
or access logger. Query records have command kind, bounded verb, input length,
`execution=not_supported` and error code where applicable.

Bounds: 16 KiB packet; 32 active connections; 3 s read/write idle timeout;
30 s connection lifetime; 32 post-auth packets. Oversized, partial, out-of-order
and timed-out packets close the connection without retaining their payload.
Logger rotates at 1 MiB to `.1`, `.2`, `.3`, four files total; the adapter reads
all retained generations using stable source IDs. Collection must keep up with
this finite retention. Log failure closes before accepting
further activity. These are producer limits, not an Internet-scale load claim.

## Tests

```bash
python -m pip install -r decoys/database/requirements-dev.txt
python -m pytest decoys/database/test_server.py tests/e2e/test_kali_zip.py -q
```

The tests use actual PyMySQL protocol traffic over ephemeral loopback ports,
malformed-wire checks, schema validation, inert ZIP verification and privacy
checks. They do not contact `192.168.77.20`.

## Integrated Kali mode

The backend, source registry and adapter in this release accept schema 1.2.
Use deployment/KALI_FOUR_RUNBOOK.md rather than the superseded teammate handoff.
Existing web block is not MySQL enforcement.

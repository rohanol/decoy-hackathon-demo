# Cowrie event field inventory (M2)

Image reference: `cowrie/cowrie@sha256:baf351038db967704dfa39f7ce860e8875c9456cdab72a9d3257c4247211050d`.

The entries below describe the adapter's current field consumption and the synthetic fixture. They are not a claim that a live container was inspected in this environment. Confirm the exact event catalogue and fields against the pulled image before enabling a new mapping; `deployment/pin_cowrie.sh` extracts the pinned image's config and filesystem, but live event output still requires the Linux lab check.

| Cowrie event | Observed fields in fixture / mapper input | SOC mapping |
|---|---|---|
| `cowrie.session.connect` | `timestamp`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `session`, `protocol`, `sensor`, `message` | `connection_open`; source address, source port and session retained |
| `cowrie.client.version` | `timestamp`, `session`, `version`, `sensor`, `message` | Buffered by session and attached once to its next mapped event as `client_version` |
| `cowrie.login.failed` / `cowrie.login.success` | `timestamp`, `src_ip`, `session`, `username`, `password`, `message`, `sensor` | Auth event; username bounded; password hashed to `password_sha256`; raw password/message dropped |
| `cowrie.command.input` | `timestamp`, `src_ip`, `session`, `input`, `message`, `sensor` | `command_input`; bounded `input` becomes `attributes.command` |
| `cowrie.session.closed` | `timestamp`, `src_ip`, `session`, `duration`, `message`, `sensor` | `connection_close`; duration is not yet surfaced |
| `cowrie.session.file_download` | `timestamp`, `src_ip`, `session`, `url` | Currently not mapped. Fixture row is synthetic and does not establish that this event is emitted by this image or that a transfer succeeded. |
| `dgsoc.network.denied` | Team handler emits `command`, plus Cowrie's session identity and event timestamp | Custom event emitted only when the mounted canned network command handler actually runs. Adapter records a `command_input` with `network_attempt_outcome=denied` and `real_execution=false`. `decoys/ssh/check_image.py` asserts dispatch using Cowrie's real event emitter when the pinned image is available. |

`sensors/tests/fixtures/cowrie_sample.json` is synthetic, sanitized test data. Password fields and credential-bearing message text are removed. `sensors/tests/fixtures/web_sample.jsonl` is also synthetic. Neither fixture is a real sensor capture. Live sanitised samples and forwarding/SFTP behaviour remain pending on the Linux defender.

Do not expand SSH mappings from upstream names alone. Pin each additional event to evidence from this image, add a redacted fixture, and distinguish request, success, denial, and actual file bytes. Shell command stubs do not prove that SFTP/SCP protocol channels are disabled; verify those channels separately.

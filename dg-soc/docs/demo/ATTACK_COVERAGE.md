# ATT&CK Coverage and Decoy Intent

This map describes what the current prototype can observe. A technique listed here is an interpretation of decoy interaction, not proof that a production host was compromised or that the same person performed other activity. Rule evidence and its `attempted` / `emulated` status remain authoritative.

## Sweep and Seek labels

- **Sweep**: a low-interaction service intended to collect broad, opportunistic probes (for example authentication attempts).
- **Seek**: a richer synthetic environment with planted breadcrumbs or bait intended to elicit follow-on interaction.

These labels describe decoy design intent. They do not classify an actor, establish intent, or imply that every session is a targeted campaign.

| Decoy | Intent | What is observed | ATT&CK mapping in this build | What it cannot establish |
|---|---|---|---|---|
| Cowrie SSH (`ssh-decoy-01`) | Seek | Authentication attempts; commands submitted to an emulated shell; reads from the fake filesystem | R01: T1110.001 password guessing (`attempted`). R02: T1059.004 command submitted (`emulated`). R03: T1083 `ls`/`find` submitted (`attempted`). R04 maps T1005 only to a read from the SSH decoy's emulated filesystem (`emulated`). | Commands are not executed on a real host. The fake file is not production data. Login acceptance is not proof of a real account compromise. |
| Web portal (`web-decoy-01`) | Seek | Supported URL/body attack indicators, hidden-path probing, synthetic file responses, and honeytoken presentations | R07: T1190 supported web attack pattern (`attempted`). R08: T1595.003 repeated path probing (`attempted`). R04 synthetic HTTP file serving has no technique ID. R09 honeytoken reuse has no technique ID and does not establish identity. | A matched pattern is not successful exploitation. A fake download is not collection from a real system. A token presentation does not prove who used it. |
| MySQL auth decoy (`db-decoy-01`) | Sweep | Connection and challenge-response authentication outcomes; query text is not executed | R11: T1110 authentication attempts (`attempted`). | The challenge-response proof does not reveal or identify a password. No database query executes; no database access or exfiltration is claimed. |
| SMB file decoy (`file-decoy-01`) | Sweep | Authentication and bounded file operations against an emulated share; accepted writes are kept inert or discarded | R11: T1110 authentication attempts (`attempted`). R12: inert content written to a synthetic share has no technique ID. Synthetic file serving has no technique ID. | No real share or production file is accessed. A stored upload is not executed, unpacked, or given a malware verdict. |

## Coverage boundary

The prototype covers selected **attempts and emulated outcomes** on four decoys. It does not monitor endpoints or production network traffic. It cannot establish successful exploitation of real systems, persistence, privilege escalation, lateral movement, real data theft, malware execution, actor identity, or production impact. Absence of an alert means only that these sensors and rules did not produce a matching observation; it does not show the behavior did not happen.

Source attribution is biased by design: activity is observed because it reached a honeypot. It is not a representative sample of ordinary production activity, and an IP address may represent multiple people or systems. Confirm cross-decoy links only through analyst review and the evidence shown; do not treat shared IP alone as identity proof.

The map follows the current rule implementations and API evidence boundaries. It is not an ATT&CK heatmap and does not claim full technique coverage.

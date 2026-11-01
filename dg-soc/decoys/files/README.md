# File-service integration status

`assets/backup.zip` is inert synthetic bait for the gateway's explicit
`/backup/backup.zip` route. It contains only a text notice and synthetic CSV.
It is not executable and includes no real credentials or organization data.

The current v1.1 ingest contract accepts only `ssh-decoy-01` and `web-decoy-01`.
It has no SMB sensor, SMB protocol observation, or database sensor event types.
Do not relabel Dionaea, gateway, or database observations as `web-decoy-01`.
The current M4 web handler also derives `src_ip` from the socket peer and does
not consume a trusted-proxy header, so deployment behind this HTTP gateway needs
an M4-owned, single-proxy trust change before events can retain attacker IPs.

## SMB candidate assessment

Dionaea is a real SMB honeypot and is GPL-2.0-or-later. Its upstream docs say the
normal configuration enables the emulation processor for shellcode detection,
stores captured downloads, and can submit files to external services. Those
features conflict with this lab's no-emulation, no-payload-persistence, and no-
egress bounds. The current release has no tagged releases in the upstream repo.
A safe pinned build and SMB-only handler configuration were not validated here;
therefore no Dionaea container is enabled or advertised as working. Before
integration, pin an audited commit and image digest, disable emu/download/submit
and all unrelated services, verify event output and license inventory, run under
an unprivileged identity with read-only root and bounded tmpfs, and confirm the
SMB negotiation/command behavior on Linux. Backend ingestion additionally needs
M3's frozen `file-decoy-01` contract.

Upstream references for this assessment:
- https://github.com/DinoTools/dionaea (protocol list, license and release status)
- https://github.com/DinoTools/dionaea/blob/master/doc/html/index.html (processors, downloads and submit configuration)
- https://github.com/DinoTools/dionaea/blob/master/conf/dionaea.cfg.cmake (default emulation processors)

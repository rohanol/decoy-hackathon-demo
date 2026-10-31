# M2 Linux deployment and physical checks

Run the decoys on Laptop B directly in Linux with Docker Engine. Use the isolated Ethernet lab only; turn Wi-Fi off and remove the default route during a run. Do not use Docker Desktop or a NATed VM for the source-IP proof.

## Prepare Laptop B

1. Configure the wired interface as `192.168.77.20/24` and Laptop A as `192.168.77.10/24`; follow [`deployment/LAB_NETWORK.md`](../deployment/LAB_NETWORK.md).
2. Install Docker Engine, Docker Compose plugin, Python 3.11 and `iproute2` tools before the offline run. Pull the pinned Cowrie image while internet is available, then disconnect Wi-Fi.
3. From `dg-soc/`, create or review `deployment/lab.env` with exact attacker IPs only. Never add the defender, loopback, a subnet, or a range to `ATTACKER_IPS`.
4. Prepare state and the Cowrie emulated filesystem:

   ```bash
   bash deployment/bootstrap_state.sh
   bash deployment/pin_cowrie.sh
   bash decoys/ssh/build_fs.sh
   ```

   `pin_cowrie.sh` needs internet and Docker. Do not run it during the demonstration.

5. Start the application stack and services:

   ```bash
   docker compose -f deployment/docker-compose.yml --env-file deployment/lab.env up -d --build
   python3 sensors/adapter.py
   bash deployment/preflight.sh
   ```

   Keep the backend and frontend bound to `127.0.0.1`; only ports 2222 and 8080 should be published on `192.168.77.20`.

## Physical checks still pending

- Verify the pinned image's actual `cowrie.cfg` option names and mounted paths; run `ls` and `cat notes.txt` over SSH as `dg_demo`.
- From Kali, connect to `192.168.77.20:2222` and `:8080`; confirm Cowrie records `src_ip=192.168.77.10`, not a bridge/NAT address.
- Confirm collector heartbeat advances while idle and after ingestion; inject a temporary backend rejection and inspect sanitized quarantine before checkpoint movement.
- Verify the web sensor logs `synthetic_file_access` only after the fixture bytes are read and reports denied policy requests with action ID and policy revision.
- Check SFTP/SCP subsystem behavior separately from canned shell commands. Demonstrate denied forwarding/transfer attempts and confirm no network egress.
- Run a full response preview/apply/denial/revoke path and capture its matching live-run provenance. Do not claim this physical path passed until it is performed.

Record the commands and their actual outputs in the release handoff. Current automated tests do not replace these hardware, Docker, source-IP, channel, or egress checks.

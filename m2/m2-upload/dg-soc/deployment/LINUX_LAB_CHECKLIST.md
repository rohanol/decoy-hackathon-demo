# Laptop B Linux lab recovery

This is the recovery procedure for the reported 31 October failures, not a claim
that the physical lab has passed. The real redacted Cowrie sample mentioned in
the team write-up was not available in this checkout; no sample is fabricated.

## 1. Choose a host that can preserve the peer IP

Use native Linux Docker Engine, a Linux live USB, or Linux Docker Engine inside
a VM bridged to the wired NIC. Give Laptop B `192.168.77.20/24`, and Kali
`192.168.77.10/24`. See `LAB_NETWORK.md`. Docker Desktop/WSL is not supported by
this lab procedure. A bridged VM is only accepted after the real-IP check below.

Never substitute `172.21.0.1` with a fixed guessed attacker IP or trust a
client-supplied `X-Forwarded-For`. Information lost at a NAT boundary cannot be
recovered from Cowrie/web request logs. The Docker gateway must never become a
response target or be added to `ATTACKER_IPS` to make the demo pass.

## 2. Prepare while Internet access is still available

Use the `fix/cowrie-lab` branch, preserving any local work before switching. From
the root `dg-soc/` directory:

```bash
bash deployment/pin_cowrie.sh
bash decoys/ssh/build_fs.sh
python3 decoys/ssh/check_image.py
bash deployment/bootstrap_state.sh
```

The default image is the exact tested digest
`cowrie/cowrie@sha256:baf351038db967704dfa39f7ce860e8875c9456cdab72a9d3257c4247211050d`.
Pinning and building use `docker create` and `docker cp`; no container shell is
required. The trusted generated pickle embeds both the note bytes and a single
`dg_demo` passwd entry. It is git-ignored. Do not load pickles from untrusted sources.

The image check runs actual Cowrie classes in a read-only container with
`--network none`, without starting an SSH service. It verifies the real passwd
loader, the home listing, exact note contents and the canned command dispatch.

Review/install M2's sensors, response and policy from `m2/m2-upload/dg-soc/` if
they have not yet been integrated into your working `dg-soc/`. Preserve existing
owner changes; do not overwrite the entire deployment folder from an older upload.
Backend dependencies are in `requirements.txt`; the adapter runtime only needs
PyYAML. Do not install M2's dev requirements over the backend environment blindly:
the two files currently pin different FastAPI versions. Prepare the web image
and frontend dependencies before disconnecting Internet access.

## 3. Isolate and start services

On Laptop B, disconnect Wi-Fi and remove Internet access for both IPv4 and IPv6.
Do not change routing in the managed cloud task. The lab preflight is read-only;
it will report default routes rather than delete them.

```bash
docker compose -f deployment/docker-compose.yml --env-file deployment/lab.env up -d
# Start the backend, adapter and frontend using their owner instructions.
bash deployment/preflight.sh --static
```

Stop and fix every failure before the probes. `STATIC PASS` is not full lab
readiness: peer IPs have not yet been established. The Cowrie lab command registry
is mounted read-only and replaces network-capable commands with canned failures;
`wget`, `curl`, `nc`, `ftpget`, `tftp`, DNS tools and related commands do not resolve
or fetch their arguments in this profile. The host must still remain offline.

## 4. Make two manual probes from Kali, not Laptop B

From Kali only:

```bash
ssh -p 2222 dg_demo@192.168.77.20
# In the emulated session: whoami; ls -la; cat notes.txt; exit
curl --connect-timeout 3 --max-time 10 http://192.168.77.20:8080/
```

Use the seeded lab login documented by the team. Confirm the note appears and its
planted portal trail is printed. Do not run arbitrary downloads to test isolation.
Then, within five minutes, on Laptop B:

```bash
bash deployment/preflight.sh
```

`ALL PASS` now requires fresh log evidence from **both** decoys with the configured
attacker IPs, normally `192.168.77.10`. A gateway IP, stale evidence, missing log,
or malformed evidence cannot pass. Keep the probe window quiet; unexpected local
health/probe traffic is also reported so mixed peer evidence is not hidden.
The checker parses JSON with or without spaces; the original grep example did
not handle all valid JSON formatting.

## 5. Verify the demo and keep credentials out of shared artifacts

Follow `scenarios/demo_p3.md` from the isolated Kali. Confirm the SSH/web candidate
link, analyst confirmation, CSV evidence, web-only block, the next request's 403
and matching action ID, undo, and 120-second expiry. Full sensor → adapter →
backend → dashboard behavior must be checked here; the offline image test does
not establish it.

Raw `cowrie.json` can contain passwords in both structured fields and `message`.
Keep it local to the restricted lab runtime, use the adapter's normalized events
for ingest, and never commit, paste or archive raw logs. If the team supplies
`m3/cowrie_real_sample.json`, inspect/redact every field before sharing it. Take a
fresh redacted Linux sample only after the source-IP check passes.

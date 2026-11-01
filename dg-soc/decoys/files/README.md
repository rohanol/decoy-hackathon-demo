# Bounded SMB file-service honeypot

The service is an original SMB2 emulator, using **Impacket 0.13.1 packet codecs**
and SPNEGO/NTLM encoding. It does not start Impacket's general-purpose file
server, RPC, credential dumping, relay, shell or download tools.

Protocol support is deliberately narrow: direct SMB **2.0.2**, NTLMv2 and the
fixed share **backups**. Verified with an actual Impacket SMBConnection client
using preferredDialect=0x202. SMB1, SMB3, signing/encryption, RPC/IPC$, directory
enumeration and arbitrary Windows Explorer compatibility are not claimed.
Unsupported operations fail rather than accessing the host filesystem.

- `backup_ops` verifies against the NT protocol verifier for `tok_smb_01`.
  The planted value lives in the web ZIP, not in this service's credential store.
- `README.txt` and `customer_data.csv` are fixed in-memory synthetic reads.
- Uploads have flat virtual names, maximum **16 KiB**, sequential writes only,
  at most eight handles per connection. Traversal, nested/absolute paths and
  attempts to overwrite the fixed assets are refused.
- Successful close stores the upload under an opaque random `.inert` name with
  mode 0600 in a private quarantine directory. Failed or disconnected partial
  uploads are discarded. There is no parsing, unpacking, execution or verdict.
- Quarantine is capped at **8 MiB / 256 files**. When full, uploads fail; the
  service never deletes evidence automatically to create space. An operator
  must archive/remove old samples deliberately before further uploads.
- Logs contain source IP/port, connection reference, proof outcome, operations,
  lengths and digests. No password, NTLM proof, raw path/unknown username,
  file content or exception text enters the native log. Unknown names use
  keyed process-local references. Native JSONL rotates to three backup files.
- Eight active connections, 64 messages each, 64 KiB message cap, 3 s idle IO
  timeout and 60 s lifetime. Incoming data is never passed to a command or URL.

From dg-soc:

```bash
python -m pip install -r decoys/files/requirements.txt
LAB_RUN_ID=your-current-run python -m decoys.files.server --host 192.168.77.20
```

Normal deployment uses the optional four-decoy Compose file. The container is
non-root and binds port 1445 internally, published only as 192.168.77.20:445.
It needs writable log/quarantine mounts, read-only root and no capabilities.
No Docker socket or real host share is mounted.

Events are schema 1.2, sensor file-decoy-01, protocol smb. The adapter validates
the complete backend model before shipping. R12 means an upload was stored
inert; it is not a malware detection. The existing web block does not enforce
on this service. Native Kali source-IP and container/network checks must be
recorded separately from the loopback protocol tests.

Tests: `python -m pytest decoys/files/test_server.py -q`. Implementation follows
[Microsoft's SMB2 negotiation specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c9efe8ca-ff34-44d0-bfbe-58a9b9db50d4)
and NTLMv2 challenge-response semantics. No malware sample is required.

# Diagnostics and error logging

AFTAB research v1 writes structured **newline-delimited JSON** logs.

## Configuration

- `-log-level=debug|info|warn|error` (default `info`)
- `-log-file=/safe/path/aftab.jsonl` (default stderr)
- One JSON object is emitted per event with UTC time, severity, component, event, random request_id and diagnostic code.

Example for an **isolated development machine**, not a public deployment:

```sh
./aftab -mode server -listen 127.0.0.1:18443 -admin 127.0.0.1:19090 -cert lab.crt -key lab.key -db ./lab-users.json -log-level debug -log-file ./aftab.jsonl
```

Events:

| Component | Event | Code | Meaning |
| --- | --- | --- | --- |
| process | starting | ok | Binary initialized |
| gateway | listener_started | ok | TLS gateway bound successfully |
| gateway | connection_rejected | unauthorized | Missing, invalid, disabled, expired or exhausted credential |
| gateway | dial_failed | upstream_unreachable | Upstream connection could not be made |
| client | listener_started | ok | Local SOCKS listener started |
| client | connection_failed | proxy_error | SOCKS/TLS connection failed |
| admin | listener_started | ok | Local API listening |

Log data deliberately excludes credentials, target hostnames, IPs, traffic payloads and destination ports. It does **not** contain per-user web history.

## Read and filter

```sh
tail -n 100 aftab.jsonl
grep '"level":"ERROR"' aftab.jsonl
grep '"component":"gateway"' aftab.jsonl
grep '"code":"unauthorized"' aftab.jsonl
```

Do not share log files until manually reviewed. Redaction applies to structured field *names*, not arbitrary text within unknown third-party error strings.

## Limitations

This is the first diagnostics milestone, **not** a complete observability platform. In particular:
- Correlation IDs are per event; they are not yet persistent across a full end-to-end connection.
- Logs have no built-in rotation, retention policy, quotas, metrics, dashboard or download endpoint.
- Some legacy Go fatal/error messages are still unstructured. They are not to be used as a secure audit log.
- Current file permissions are requested as 0600 when creating a file, but an existing file's permissions are not reset.
- Redaction should be audited and fuzz-tested before production use.

Use your host's existing approved log rotation tooling in a lab; do not expose logs or administrator API to the internet. No changes to the existing VPS, 3x-ui or Xray are required.

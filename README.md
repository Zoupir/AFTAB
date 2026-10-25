# AFTAB Research

Experimental independent secure networking platform, separate from Xray and 3x-ui.

**Status: early research prototype, NOT a production VPN or verified censorship-resistant system.**

## Release v1.0.0 (local test package)
The initial source and Linux/Windows executables are distributed as `AFTAB-Research-v1.0.0.zip` in the associated ChatGPT project. This repository is being populated with reviewed source and reproducible build infrastructure. Do not treat the existing laboratory binary as safe for public users.

## Implemented in the initial prototype
- Go TCP gateway over TLS 1.3 with pinned leaf certificate on the client.
- Per-user access tokens and basic expiration/quota accounting.
- Loopback-only local management panel.
- Local SOCKS5 TCP CONNECT client and a browser-based launcher.

## Not implemented
- OS-wide VPN/TUN, Android or native desktop app, UDP tunneling, fail-closed behavior.
- Adaptive multiple transport protocols, stealth or guaranteed censorship resistance.
- Independently audited protocol or novel cryptographic algorithm.

## Security
Never commit credentials, private keys, tokens, client configuration with secrets, or VPS details. Do not expose admin listeners publicly. There are known limitations in token storage, accounting and connection controls; restrict testing to a controlled lab.

## Research direction
Use independently reviewed cryptography. Treat a new transport/framing design as a falsifiable hypothesis; benchmark against existing methods, including failure conditions, before claiming novelty.

See [research plan](docs/RESEARCH.md) and [security scope](SECURITY.md).

## Diagnostics
Structured JSON event logging is implemented for process startup, gateway and SOCKS failures and the local administrator API. See [diagnostics and troubleshooting](docs/DIAGNOSTICS.md). Privacy-sensitive fields are intentionally excluded. This is experimental diagnostics, not a complete security audit log.

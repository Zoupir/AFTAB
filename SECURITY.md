# AFTAB research security policy

This is **not a production-ready VPN**. Do not use it to protect people facing targeted monitoring or censorship enforcement.

- Do not commit keys, secrets, client configuration, real server addresses or tokens.
- Keep administration bound to loopback and gate access with an independently secured administration channel.
- No custom encryption primitive is approved. Use established, independently audited primitives.
- Current quota handling is approximate and should not be treated as hard enforcement.
- Source review, fuzz testing, threat modelling, independent audit, and live OS-level tests are required before broader use.

Report vulnerabilities privately to the repository owner; do not publish exploit details before remediation.

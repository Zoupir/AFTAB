# AFTAB Desktop preview | Four-language graphical client

**Status:** experimental browser-managed TCP SOCKS5 client. This is not an operating-system VPN or a hardened public release.

## Windows user experience

1. Download the `aftab-research-preview` artifact from a **successful GitHub Actions run**.
2. Extract `aftab-windows-amd64.exe` and double-click it.
3. The Windows executable opens the local AFTAB Desktop interface in the default browser (`127.0.0.1:19091`). The browser is the graphical user interface, and the executable remains running while the interface is in use.
4. Select Persian, English, German or Arabic.
5. Enter your gateway's reachable `host:port`, account token and pinned TLS certificate SHA-256 fingerprint; press **Save**.
6. Press **Test TLS** to check that the endpoint is reachable and that its leaf certificate matches the pinned fingerprint.
7. Press **Connect** to start the local SOCKS5 proxy at `127.0.0.1:10808`; press **Disconnect** to stop it and close tracked client TCP sockets.
8. A read-only section shows up to 30 recent structured diagnostic entries. No token is displayed after saving.

**This does not automatically route Windows traffic.** Each program must explicitly use the local SOCKS5 proxy (or be configured by other authorized software). A successful TLS test only checks the encrypted handshake and certificate pin. It does not prove an account token is accepted, a destination is reachable or internet traffic flows through the proxy.

### Security decisions

- The UI binds to numeric loopback only and rejects non-loopback peer addresses and untrusted Host headers.
- Each process generates a new single-use startup URL ticket. After validation, it sets an HttpOnly, SameSite=Strict local session cookie.
- State-changing forms require CSRF tokens and an Origin check.
- The account token is not shown in HTML after storage, and diagnostics log only event codes, not private destination addresses or traffic payloads.
- The client configuration is written to the OS user configuration directory (`AFTAB/desktop.json`). It currently contains the account token in plaintext and must be protected by the user account and filesystem permissions. A future release needs Windows DPAPI or another OS credential vault.
- By default the desktop logger creates an AFTAB user-data log at `AFTAB/logs/events.jsonl`. Log retention/rotation is not yet implemented.
- This application is not signed and no native graphical installer exists yet. Browser control is the current graphical interface.

### Server compatibility and lab restrictions

The present research gateway **only binds to local loopback**, intentionally. Therefore it cannot yet accept direct clients across the public internet. Do not expose the gateway or control panel to the internet to work around this restriction. Local same-host tests and securely administered isolated lab transport tests are supported. An internet-facing, independently audited gateway design is future work.

The release gate for public use remains: real Windows QA; reliable end-to-end reconnect and disconnect tests; private credential storage; completed transport threat model; IPv4/IPv6 policy; UDP/TUN handling; Android app; hardened remote administration; automatic upgrades and signed distributions.

## Graphical browser proxy mode (implemented October 2026)

The graphical client now starts **two** loopback listeners when connected:

- SOCKS5: `127.0.0.1:10808`, for applications that support SOCKS5
- HTTP proxy with HTTPS CONNECT: `127.0.0.1:10809`, for browsers and applications that support an HTTP system proxy

On Windows, the **Automatically configure Windows browser proxy** checkbox is an explicit opt-in in the graphical Settings form. When enabled, Connect saves the existing Windows per-user WinINET proxy settings, starts both local listeners and sets the system HTTP/HTTPS proxy to `127.0.0.1:10809`. Disconnect restores the previous settings. A separate watchdog process monitors the client and restores the previous settings if the main application process exits unexpectedly. On the next startup, a leftover backup is also recovered.

This mode makes AFTAB useful for compatible browser traffic without a manual proxy extension. **It does not create a VPN TUN/TAP adapter, does not route UDP, cannot capture applications ignoring system proxy settings and is not a system-wide VPN.**

The client saves its own account token with Windows DPAPI under the invoking Windows user account. Do not share your token or copy the encrypted profile between Windows user accounts. Installer and binaries are currently unsigned previews, not security-audited releases.

The graphical **Test gateway and account** action opens a server-originated test TCP connection to `example.com:443` and confirms the account was accepted. **Test TLS** checks only the gateway's pinned TLS certificate.

### Server

Use the Linux Debian package from the same successful build. On first run the administrator chooses username/password in the four-language panel. Gateway settings can be configured for either local testing or remote-client TCP service. The administration panel remains loopback-only for safety. The remote gateway requires the administrator to open the selected firewall port through their own hosting provider firewall.

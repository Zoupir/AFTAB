# AFTAB installation preview (Windows and Ubuntu)

**Research preview only.** Current software implements a certificate-pinned TLS TCP/SOCKS5 proxy, not a complete device VPN. It has no Android client and is not independently audited. Use with disposable test accounts, not for high-risk traffic.

## Windows (graphical)
From a **successful** [GitHub Actions build](https://github.com/Zoupir/AFTAB/actions), download artifact `aftab-installable-preview` and extract `aftab-windows-portable.zip`. Run `aftab-windows-amd64.exe` and the local graphical client appears in your default browser. Choose Persian, English, German or Arabic. Add your account token, gateway `host:port`, certificate fingerprint and press Save, Test TLS, Connect.

The client binds local SOCKS5 to `127.0.0.1:10808`. Only traffic from software explicitly configured to use SOCKS5 goes through it. Disconnect stops tracked client TCP streams. The user token is encrypted using **Windows DPAPI** for the current Windows profile; the GUI never displays it after saving. This is a portable unsigned preview, not a native MSI installer.

## Ubuntu 24.04 server
The same successful artifact contains `aftab-server-amd64.deb`. Install the package using your trusted package manager on a test server. It installs a dedicated `aftab-server` systemd service. No 3x-ui or Xray files are read or modified. Existing services continue to run on their existing ports.

The AFTAB administrator panel listens **only** on `127.0.0.1:19090`. From a remote Windows computer, access it through a securely authenticated SSH local-forward, or directly from a browser running on the server. It is intentionally NOT exposed on the public internet. On first visit, the installation wizard asks the installer to choose their own administrator username, password and language. No default administrator credential exists.

Once logged in, create a test user, select Gateway Settings, choose port 18443 or another unoccupied port, and choose local-only or advanced remote-client mode. Remote mode binds `0.0.0.0:<port>` and must be explicitly enabled. The administrator panel itself stays loopback-only. Authorize the selected gateway port in your firewall only after reviewing the restrictions and server security. The UI displays the pinned TLS certificate fingerprint. Gateway settings persist and are restored after a service restart until the admin chooses Stop Gateway.

Remote mode currently restricts TCP egress to ports **80, 443, 8080, 8443**, and rejects local, private, special-purpose and cloud metadata address ranges after DNS resolution. It is not a comprehensive egress security policy.

## Debian package housekeeping

The systemd service runs as a restricted dynamic service user. State and credentials live in the AFTAB-specific state directory under `/var/lib/aftab`. The gateway does **not** start remotely until an authenticated administrator has configured it in the panel. Once deliberately enabled, its settings are restored on startup. Service logs are emitted in private JSON lines.

Never publish database, token, admin credential hash or TLS private key. Keep backup copies secured. AFTAB package names and paths are independent of any other VPN server components.

## Test sequence

1. Verify the admin login, user creation and dashboard diagnostic tab.
2. Start gateway and run GUI self-test. That test proves only a local TLS handshake.
3. Confirm the server port and Windows client gateway address match, and transfer the account token and certificate fingerprint privately.
4. Use the Windows GUI's Test TLS action, then Connect.
5. Configure a test browser/application to use the local SOCKS5 port, and check actual HTTP reachability.
6. Disconnect and verify new traffic fails through that SOCKS5 endpoint.
7. Review errors in dashboard diagnostics on both machines.

**Caveats:** No system-wide TUN device, UDP VPN, Android APK, protocol camouflage, public admin interface, signed installer, automated update, tested network failover or independently verified anonymity in this preview.

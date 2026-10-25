# AFTAB graphical administration | research preview

This version adds a real, browser-based administration interface that can be used without shell commands after launching the server process.

## First run

**Windows laboratory:** Download the Windows preview build from a **successful GitHub Actions run**, extract the executable to a writable directory and launch `aftab-windows-amd64.exe`. With the default options, the program starts the administration listener at `http://127.0.0.1:19090` and attempts to open your browser automatically.

**Linux laboratory:**

```bash
./aftab-linux-amd64 -mode server -db ./data/aftab-users.json -log-file ./data/aftab.jsonl
```

Then open `http://127.0.0.1:19090` **on the same machine**. On a headless remote server, reach this local listener only through an authenticated local SSH port forwarding session. Do not publish the administration port on the public internet.

**The first browser page is the setup wizard**. It requires the person installing AFTAB to choose:

- Administrator username, 3–48 ASCII letters, numbers, dots, hyphens or underscores
- Administrator password, at least 12 characters, and confirmation
- Interface language: Persian, English, German, or Arabic

There is **no default administrator username or password**. Do not forget the password: no insecure email-recovery workflow or publicly accessible password reset endpoint is provided.

The password is stored as a per-install random-salt PBKDF2-HMAC-SHA256 verifier (600,000 iterations), rather than as plaintext. Credentials are saved separately beside the users database in `<db>.admin.json`. The credentials file is created with restricted permissions.

## Daily operation

After setup, log in with the chosen username and password. The session uses an HttpOnly, SameSite=Strict cookie and a CSRF token on state-changing forms. The dashboard presents user management, diagnostic events and the experimental TLS gateway settings.

Use **Gateway settings** to select a local port and start a TLS 1.3 gateway. On initial start, a disposable self-signed certificate is created locally. The panel shows its SHA-256 fingerprint and provides a **Test** action that performs a local certificate-pinned TLS handshake.

**Important:** A successful test verifies only the local TLS connection, not an Internet connection, censorship resistance, a full VPN tunnel or OS-wide traffic routing.

When creating a user, the account token is shown **once**. Store it securely; the management page does not expose previously created tokens.

The administration interface intentionally only listens on numeric loopback (default `127.0.0.1:19090`). Internet-facing provisioning, mobile clients, public gateway binding, operating system VPN/TUN, safe deployment and independent auditing are **not delivered** in this research preview.

## Internationalization

UI dictionaries are maintained in `internal/dashboard/translations.go` and template RTL layout is automatically enabled for `fa` and `ar`. Interface language is user-selectable on the setup and login screens or by language links on the dashboard. New locales should add a dictionary; English is the fallback.

## Diagnosing errors

Start with `-log-level info -log-file ./data/aftab.jsonl`. Open **Diagnostics** to inspect the 100 most recent structured events. Sensitive user traffic and tokens should not be logged. See [diagnostics](DIAGNOSTICS.md).

## Security and packaging limitations

- This is a research preview and must not be used as a production security VPN.
- The server code still has an experimental forwarding protocol and incomplete anti-abuse controls.
- Gateway auto-start and automatic rotation of TLS certificates are not implemented.
- Credentials have no graphical recovery or change-password screen yet.
- Public multi-user hosting must wait for a reviewed HTTPS control plane, explicit trust boundaries, rate limits and threat modelling.
- Linux and Windows builds are CI artifacts rather than signed installers; Android and desktop native VPN clients do not yet exist.

## Change the administrator password

Use **Administrator account** in the side menu. Enter your current password, a new password of at least 12 characters, and its confirmation. A successful change invalidates existing administrator sessions and redirects to sign-in.

## Local-only recovery after a forgotten password

There is deliberately **no publicly available reset link or secret default administrator password**. A legitimate system owner must stop AFTAB, securely back up and move aside the local `<db>.admin.json` credential file, and restart AFTAB to run first-time setup again. This requires trusted filesystem access; it cannot be done from an unauthenticated webpage. The user database remains separate from the credential file. Review local operating-system permissions before starting the wizard.

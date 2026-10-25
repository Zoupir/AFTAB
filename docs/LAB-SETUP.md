# AFTAB v1 laboratory setup (independent of 3x-ui)

**This is a SOCKS5 research prototype, not a complete VPN.** It cannot claim anonymity, evasion or protection from a powerful network monitor. Never put real clients on this build.

## Obtain build outputs

Open GitHub **Actions > Go checks and preview builds**, select a successful run on main and download the `aftab-research-preview` artifact. It includes amd64 Linux and Windows binaries. Builds are made from the current GitHub source. If no successful run exists, troubleshoot CI before installation.

## Safety boundaries

- The Go server intentionally permits only loopback listeners (127.0.0.1 or ::1).
- Do not open its gateway or admin ports to the internet.
- Do not overwrite, modify, or restart 3x-ui / Xray.
- Use a separate test environment. Strong authentication, ACLs, anti-abuse measures, native VPN networking and audits are missing.
- Backup before migrating away from the previous research prototypes. Their database formats may be incompatible.

## Building from source

```sh
go test ./...
go build -o aftab ./cmd/aftab
```

## Run in a local Linux-only lab

Use a disposable Linux VM/container with Go and OpenSSL. Generate a disposable TLS certificate:

```sh
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3 -keyout lab.key -out lab.crt -subj "/CN=lab.invalid"
chmod 600 lab.key
./aftab -mode server -listen 127.0.0.1:18443 -admin 127.0.0.1:19090 -cert lab.crt -key lab.key -db ./lab-users.json
```

First initialization prints an admin bearer token; keep it private. The local admin API requires authorization. To create a laboratory account:

```sh
curl -sS -H "Authorization: Bearer <ADMIN_TOKEN>" -H "Content-Type: application/json" -d '{"name":"lab","days":1,"gb":1}' http://127.0.0.1:19090/api/users
```

This returns a separate user token. Don't paste real tokens into issue reports or public repositories.

Compute the leaf certificate SHA256 pin:

```sh
openssl x509 -in lab.crt -outform DER | sha256sum
```

Create a client-only JSON file with `server`, `listen`, `token` and `pin` fields; keep it outside the repository. `server` is the reachable endpoint and `listen` should remain `127.0.0.1:10808`. Then:

```sh
./aftab -mode client -config client.json
```

An HTTP client configured for SOCKS5 can use the local listener. Traffic from other applications does not go through the proxy automatically.

## Important nonfeatures

There is **no native Windows graphical client** in this GitHub code yet, despite earlier proof-of-concept launchers existing in separate local bundles. There is no Android application, no operating-system TUN mode, and no production-level quota enforcement. Existing v1 GitHub admin is a local API, not a polished dashboard.

## Research acceptance gates

- Reproducible green CI on supported platforms
- Validated packaging, basic unit tests and independent source review
- Server and client integration tests
- Private destination restrictions and resilience against resource exhaustion
- Leak tests and safe failure behavior
- UX and portability tests on real Windows/Android devices
- Adversarial transport study before claims about obfuscation or censorship resistance

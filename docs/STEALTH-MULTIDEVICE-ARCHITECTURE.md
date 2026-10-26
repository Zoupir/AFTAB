# AFTAB | Resistance to Blocking & Multi-Device Architecture (2026-10-26)

## Goal
AFTAB must provide full-tunnel connectivity on Windows 10/11 and Android, with an independent credential/device profile for each friend; minimize traffic fingerprinting and operational single points of failure. **No VPN is undetectable**, including WireGuard, AmneziaWG, REALITY, and Hysteria. Never claim "100% stealth".

## Design decision: two transports, not bare WireGuard or the current TCP research proxy

### Primary: AmneziaWG 3.1 (UDP), Windows + Android
- Use the mature, externally audited WireGuard cryptographic construction with AmneziaWG 3.1 traffic-obfuscation mechanisms (variable length and packet timing, encrypted header metadata, optional mimicked protocol characteristics). Support 3.1-only clients; avoid older 1.x templates.
- Native Windows full tunnel uses the official AmneziaWG client and Wintun; native Android uses the official AmneziaWG client and Android VPNService. No handmade unreviewed TUN driver.
- The server requires its own dedicated UDP listener, own interface/subnet, NAT, forwarding, DNS and strict egress policy. **No changes whatsoever to existing Xray or 3x-ui.**
- Unique Curve25519 client keys and internal IPv4 for each *device*, not shared credentials. When a friend has a phone + a PC, create separate peers and revoke independently.
- Protected import file (.conf) or QR for Android, exported individually and only once. Avoid ever sending private peer keys into logs or a public URL.
- Traffic and expiry caps are **management-layer enforcement**, not inherent AmneziaWG capabilities. They must be implemented and integration-tested against the interface; do not label quota UI working before then.
- IPv6 and DNS leak prevention are release gates. An IPv4-only server profile must not silently leak IPv6/UDP over an unprotected network; enforce a tested client/server policy.

### Fallback: VLESS + REALITY over TCP
- If UDP is blocked, maintain a **separate authorized fallback** based on an established, maintained core (e.g. Xray VLESS+REALITY) and a full-tunnel client implementation, not the custom AFTAB v0.4 TCP proxy alone.
- The already-running 3x-ui / Xray Reality on the existing VPS must not be altered. Any new fallback port or process requires approval and a free-port/firewall audit.
- Do not use fabricated TLS/HTTP handshakes or unverified homegrown cryptography. Follow upstream's official fingerprint and certificate/session verification.
- REALITY is not a guarantee of camouflage and cannot ensure resilience to IP-level or ASN-level blocking.

## Threat model / hard release requirements
1. **Passive DPI:** hide fixed WireGuard fingerprints with AWG 3.1, TLS/REALITY for blocked UDP; evaluate from networks where the user operates rather than assuming effectiveness.
2. **Active probing:** unauthenticated contacts should not reveal an admin console or an open TCP proxy. Leave all administration bound to 127.0.0.1; access only over authenticated SSH tunnel.
3. **IP blocking:** obfuscation cannot hide the VPS destination IP from a network operator. Genuine redundancy requires a second endpoint/IP under user's control. Do not imply one server solves this.
4. **Traffic analysis:** obfuscation reduces some distinguishing patterns but cannot eliminate timing, packet volume, or usage-correlation signals.
5. **Credential sharing:** one secret/profile per device, independent revocation, role-based admin, bounded sessions, quotas, expiry, and audit without sensitive tokens.
6. **Endpoint policy:** route all necessary TCP/UDP/DNS through VPN when on, prevent leaks on unexpected exit (kill-switch with consent), and make split tunnel explicit if enabled.
7. **Risk to production VPS:** snapshot, verify CPU/RAM and free ports, install new packages/service independently, never restart or reconfigure existing 3x-ui/Xray, no UFW flush and no full nftables reset.
8. **Platform distribution:** Windows installable/signed when feasible; Android native VPNService app or officially maintained AWG app with importable AFTAB-issued profile. Avoid sending raw server SSH password to friends.
9. **Untrusted or banned binaries:** do not ask users to disable Windows Defender; investigate detections, use signed trusted distribution when possible.
10. **Security upgrade path:** protocols/parameters versioned, peer key rotation, revocation, backup and rollback. Keep server secrets out of exported friend profiles.

## Practical implementation order
1. Add a separate AFTAB admin **Device Profiles** resource: create phone or PC for a named friend, unique key pair and non-overlapping address. Export one-time AmneziaWG 3.1 .conf/QR; disable/revoke peers.
2. Build isolated AWG 3.1 server package and dry-run configuration validation on Ubuntu 24.04. Do **not** auto-deploy on live VPS; explicit opt-in after conflict audit.
3. Test full-tunnel TCP + UDP, DNS, IPv4/IPv6 leak, uploads/media, WhatsApp and Telegram on Windows + Android, with the actual user's network.
4. Add second transport fallback, disconnect behavior, rolling updates and operational health checks.
5. Only then call release "usable as system-wide VPN". Existing v0.4 remains the working browser proxy until replaced.

## External basis
- https://docs.amnezia.org/documentation/amnezia-wg/ (AWG 3.1 capabilities and restrictions)
- https://github.com/amnezia-vpn/amneziawg-windows-client/releases
- https://github.com/amnezia-vpn/amneziawg-android/releases
- https://hysteria.network/docs/advanced/Full-Server-Config/ (QUIC/UDP, experimental obfuscation fallback alternative)

## Explicit current status
AFTAB v0.4 is a working *browser TCP proxy* only. AFTAB has **not yet deployed AWG, an Android client, or a system-wide TUN VPN**. This document is the architecture and security acceptance criteria, not proof of a released full VPN.

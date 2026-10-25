# Research plan: AFTAB

## Goal
Evaluate a user-friendly, secure, multi-transport network access application independent of Xray/3x-ui. Novelty is an open research question, not an established fact.

## Hypotheses
1. Decoupling application sessions from a particular transport may improve recovery after a connectivity change.
2. Locally informed transport selection may reduce failed connection attempts compared to static configuration.
3. Simplified provisioning may substantially reduce configuration errors for nontechnical users.

## Baselines
Compare with plain TLS TCP, QUIC, SSH port forwarding and established open-source VPN transports. Record packet loss, completion ratio, failover latency, throughput and connection setup time.

## Guardrails
Use standard cryptography and authenticate every negotiated session. Test leakage, replay resistance, resource exhaustion, destination ACLs and configuration failures. No claims of being undetectable without an independent adversarial evaluation.

## v1 limitations
Initial v1 is a TCP SOCKS5 research proxy. It is not OS-wide VPN, Android app or a novel encryption scheme. Do not use it for high-risk deployment.

## Frame codec milestone (October 2026)
A bounded, versioned binary framing codec and tests now live in `internal/frame/`.
This is deliberately **not wired to the network gateway** yet. The first version uses a fixed 19-byte header (magic, version, session ID, sequence, length), supports payloads up to 65536 bytes, and rejects truncation and oversized claims before allocation.
The codec has no encryption or replay protection of its own; those properties must be provided and verified in the future authenticated transport layer.

## Release gate
CI success and reproducible cross-platform builds are not yet confirmed by an accessible workflow run in this session. Do not publish a production release until that gate is green and independent security review is complete.

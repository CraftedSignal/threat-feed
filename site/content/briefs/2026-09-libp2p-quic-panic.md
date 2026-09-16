---
title: Remote Denial of Service in libp2p-quic via Certificate Expiry Race
slug: 2026-09-libp2p-quic-panic
description: A malicious peer can trigger an application crash in libp2p-quic (< 0.13.1) by initiating a QUIC handshake and delaying the final TLS fragment until the peer certificate expires, causing an unhandled panic.
date: "2026-09-16T01:05:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:libp2p:libp2p-quic:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - libp2p
  - rust
vendors:
  - libp2p
products:
  - libp2p-quic (< 0.13.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Any application exposing an affected libp2p-quic listener can be crashed by a network peer that performs a valid-looking QUIC/TLS handshake with attacker-controlled timing.
    confidence_band: high
cves:
  - id: CVE-2026-61544
references:
  - https://github.com/advisories/GHSA-5hq8-qhww-jm7q
  - https://github.com/libp2p/rust-libp2p/blob/969b707bf1177ebebd1febc285c3fd22793b95c5/transports/quic/src/connection/connecting.rs#L65-L66
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade libp2p-quic to 0.13.1 or later
      owner: Development
      due: 48h
      evidence: 'Affected Packages: rust/libp2p-quic (vulnerable: < 0.13.1)'
  mitigation_plan:
    - priority: immediate
      action: Upgrade to v0.13.1
      owner: Development
      addresses: CVE-2026-61544
      evidence: 'Affected Packages: rust/libp2p-quic (vulnerable: < 0.13.1)'
---

The `libp2p-quic` crate is susceptible to a remote unauthenticated denial-of-service vulnerability (CVE-2026-61544) resulting from improper error handling during the QUIC/TLS handshake process. The vulnerability stems from a race condition where the library performs two distinct certificate validations. The first validation succeeds when the connection is established; however, a second, post-handshake validation is performed during the upgrade path. If a malicious peer presents a valid, short-lived certificate and intentionally delays sending the final TLS 1.3 handshake fragment until after the certificate's validity period has elapsed, the second validation check fails. Because the library incorrectly assumes this second parse cannot fail, it triggers an unhandled `expect()` call, leading to a process panic and application crash. This affects any application utilizing `libp2p-quic` versions prior to 0.13.1.

## Attack Chain

1. Attacker initiates a standard QUIC connection to a listener running an affected version of `libp2p-quic`.
2. Attacker provides a legitimate, short-lived libp2p TLS certificate.
3. The target's `libp2p-tls` component successfully parses and validates the certificate during the initial handshake.
4. The Quinn protocol stack reports the handshake completion to the application.
5. Attacker purposefully withholds the final client handshake fragment packet.
6. Attacker waits until the certificate has expired while remaining within the application's QUIC handshake timeout threshold.
7. Attacker transmits the delayed final handshake fragment to the target.
8. The target performs the post-handshake certificate re-parse, encounters a failure due to the expired certificate, and triggers an unhandled panic.

## Impact

Successful exploitation results in an immediate, remote unauthenticated denial-of-service. Because the vulnerability triggers a process-level panic, it causes an abrupt crash of the host application, potentially impacting all active connections and services handled by that instance. The attack requires no malformed packets, making it difficult to detect via traditional signature-based protocol inspection.

## Recommendation

Prioritized actions for development and security teams:
- Upgrade `libp2p-quic` to version 0.13.1 or later to resolve the panic condition in the connection upgrade path.
- Audit network ingress traffic for an unusual frequency of long-duration QUIC handshakes that fail shortly after initiation.
- Implement process monitoring to detect service restarts or crashes associated with `libp2p-quic` dependencies.

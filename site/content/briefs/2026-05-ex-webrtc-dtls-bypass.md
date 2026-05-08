---
title: ex_webrtc Missing DTLS Fingerprint Validation Allows MITM
slug: 2026-05-ex-webrtc-dtls-bypass
description: The ex_webrtc library is vulnerable to a man-in-the-middle attack due to missing DTLS peer certificate fingerprint validation in the DTLS client role, potentially allowing interception of media and data channels when chained with insecure signaling or a peer with similar validation gaps; upgrade to versions 0.15.1 or 0.16.1 to mitigate this vulnerability.
date: "2026-05-08T17:08:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webrtc
  - dtls
  - mitm
  - vulnerability
vendors:
  - Erlang
products:
  - ex_webrtc (< 0.15.1)
  - ex_webrtc (= 0.16.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Lateral Movement
    technique_id: T1557
    technique_name: Man-in-the-Middle
references:
  - https://github.com/advisories/GHSA-qwfw-ggxw-577c
  - https://github.com/elixir-webrtc/ex_webrtc/issues/249
  - https://github.com/elixir-webrtc/ex_webrtc/pull/250
  - https://github.com/elixir-webrtc/ex_webrtc/releases/tag/v0.15.1
  - https://github.com/elixir-webrtc/ex_webrtc/releases/tag/v0.16.1
rules:
  - title: Detect ExWebrtc DTLS Handshake Without Fingerprint Validation
    description: Detects CVE-2026-44700 exploitation — identifies DTLS handshakes initiated by ex_webrtc without proper fingerprint validation, indicative of a potential MITM attack
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1557.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Insecure Signaling Protocols for WebRTC SDP Exchange
    description: Detects the use of HTTP or plain WebSocket protocols for WebRTC signaling, which can facilitate man-in-the-middle attacks by allowing SDP rewrite.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1557.001
    data_sources:
      - webserver
rules_count: 2
---

The `ex_webrtc` library, a WebRTC implementation for Erlang, is susceptible to a security vulnerability due to missing DTLS peer certificate fingerprint validation in the DTLS client role. Specifically, versions prior to 0.15.1 and version 0.16.0 fail to properly validate the fingerprint of the peer's certificate when acting as a DTLS client. This occurs when answering a remote offer with `a=setup:actpass`, which is the default behavior for browsers. This oversight eliminates a crucial component of WebRTC's mutual DTLS authentication, leaving the security of media and data channels dependent solely on the remote peer's fingerprint verification. While this vulnerability alone does not allow passive eavesdropping on SRTP media against standards-compliant browsers using TLS-protected signalling, it enables a full man-in-the-middle attack when combined with insecure signalling protocols or a peer with similar validation flaws.

## Attack Chain

1.  The attacker intercepts the initial SDP offer from a legitimate client to the vulnerable `ex_webrtc` server using insecure signalling (e.g., HTTP or plain WebSocket).
2.  The attacker modifies the SDP offer, replacing the legitimate client's DTLS fingerprint with their own.
3.  The attacker forwards the modified SDP offer to the vulnerable `ex_webrtc` server.
4.  The `ex_webrtc` server, acting as the DTLS client, initiates a DTLS handshake with the attacker using the attacker's fingerprint due to the missing validation.
5.  The attacker presents a valid certificate to the `ex_webrtc` server, completing the DTLS handshake successfully.
6.  The attacker intercepts the SDP answer from the `ex_webrtc` server, which now contains the attacker's fingerprint.
7.  The attacker modifies the SDP answer, replacing their fingerprint with the legitimate server's fingerprint.
8.  The attacker forwards the modified SDP answer to the legitimate client, establishing a secure connection between the client and the attacker, effectively completing the MITM attack and allowing interception of media and data channels.

## Impact

This vulnerability allows an attacker to perform a man-in-the-middle attack on WebRTC connections using `ex_webrtc`, potentially affecting any application that relies on this library for secure communication. Successful exploitation could lead to the interception and manipulation of audio/video media (SRTP) and data channels (SCTP-over-DTLS). The impact is heightened when used with insecure signaling methods, increasing the attack surface. While the number of affected applications is unknown, the potential for widespread compromise of WebRTC-based communication channels exists.

## Recommendation

*   Upgrade `ex_webrtc` to version 0.15.1 or 0.16.1 to patch the missing DTLS fingerprint validation as advised in the advisory ([https://github.com/advisories/GHSA-qwfw-ggxw-577c](https://github.com/advisories/GHSA-qwfw-ggxw-577c)).
*   Deploy the Sigma rule `Detect ExWebrtc DTLS Handshake Without Fingerprint Validation` to identify potentially vulnerable `ex_webrtc` instances negotiating DTLS connections without proper fingerprint validation.
*   If insecure signaling protocols (HTTP/plain WebSocket) are in use, migrate to secure alternatives like HTTPS or WSS to prevent SDP rewrite attacks, mitigating the impact of CVE-2026-44700.

---
brief_id: brief-2026-10-23-wireguard-endpoint-hijack
event_id: brief-2026-10-23-wireguard-endpoint-hijack
revision: 1
activity_at: "2026-10-23T22:04:43Z"
title: 'WireGuard: Peer endpoint hijacking via unauthenticated UDP packets (CVE-2026-79977)'
slug: 2026-10-wireguard-endpoint-hijack
description: A vulnerability in the WireGuard implementation (subsys/net/lib/wireguard/wg.c) allows an off-path attacker to redirect peer traffic by sending an unauthenticated UDP datagram.
date: "2026-10-23T22:04:43Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - WireGuard (subsys/net/lib/wireguard/wg.c)
cves:
  - id: CVE-2026-79977
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79977
---

The WireGuard implementation in `subsys/net/lib/wireguard/wg.c` updates the peer endpoint from an unauthenticated transport-data message. In `handle_transport_data()`, if the 32-bit receiver index of an incoming message does not match a session, the code copies the datagram's source address into `peer->endpoint` using `memcpy`. Because the receiver index is unknown and unverified, an attacker can supply an arbitrary address. 

The listener, which defaults to UDP port 51820, does not filter by remote address or cryptographic identity, allowing any host capable of sending a UDP datagram to trigger this update if the peer lacks a valid handshake or current keypair. This redirects subsequent handshake initiations, keepalives, and encrypted data to the attacker-supplied address, causing a loss of availability and potential man-in-the-middle positioning. End-to-end cryptography prevents decryption or forgery of tunnel content. `CONFIG_WIREGUARD` is experimental and not enabled by default.

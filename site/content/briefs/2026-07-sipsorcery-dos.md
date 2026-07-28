---
title: 'SIPSorcery: Malformed UDP Packet Can Remotely Terminate Media Sessions (DoS)'
slug: 2026-07-sipsorcery-dos
description: A denial-of-service vulnerability (CVE-2026-54632) exists in the SIPSorcery NuGet package versions <= 10.0.8, allowing an unauthenticated attacker to remotely terminate an active RTP or WebRTC media session by sending a single malformed inbound UDP packet to the RTP/ICE socket, which exploits insufficient length checks and an exception handling flaw.
date: "2026-07-28T17:02:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - nuget
  - sipsorcery
vendors:
  - SIPSorcery
products:
  - SIPSorcery (<= 10.0.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Because the RTP/ICE port is shared/advertised in the ICE candidates, a peer or on-path attacker can reach it
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A single malformed inbound UDP packet on the RTP/ICE socket can remotely terminate an active RTP or WebRTC media session.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-28gm-jrmw-xx93
---

A high-severity denial-of-service vulnerability, tracked as CVE-2026-54632, affects versions of the SIPSorcery NuGet package up to and including 10.0.8. An unauthenticated attacker can exploit this flaw by sending a single malformed UDP packet to a vulnerable SIPSorcery RTP/ICE socket. The vulnerability stems from inadequate length checks when processing packet data and STUN attributes, which can lead to runtime exceptions such as `IndexOutOfRangeException` or `NullReferenceException`. Crucially, the UDP receive loop in `UdpReceiver.EndReceiveFrom` incorrectly responds to these exceptions by closing the entire channel rather than merely discarding the problematic packet. This systemic flaw allows a single, small, unauthenticated packet to terminate an active RTP or WebRTC media session, causing a Denial of Service. The issue is reachable during ICE connectivity checks, even before DTLS handshakes or STUN `MESSAGE-INTEGRITY` verification.

## Attack Chain

1. An attacker crafts a specially malformed UDP packet (e.g., a 1-byte packet or a STUN message with a short `XOR-MAPPED-ADDRESS` attribute length of 0-7 bytes).
2. The attacker sends this malformed UDP packet to the target SIPSorcery RTP/ICE socket, whose port is typically advertised during ICE candidate exchange.
3. The SIPSorcery application's `UdpReceiver` receives the packet and passes it for processing to `RTPChannel.OnRTPPacketReceived` or `STUNAttribute.ParseMessageAttributes`.
4. Due to insufficient length validation in these parsing routines, the application attempts to index untrusted bytes beyond the packet's bounds or with null values, leading to an `IndexOutOfRangeException` or `NullReferenceException`.
5. The `UdpReceiver.EndReceiveFrom` method, which manages the UDP receive loop, catches this application exception within a general `catch-all` block.
6. Instead of logging the error, dropping the malformed packet, and continuing the receive loop, the `catch-all` block incorrectly invokes `Close()`.
7. The invocation of `Close()` forcefully tears down the active RTP or WebRTC media session channel, resulting in a complete Denial of Service for the affected communication.

## Impact

The primary impact of CVE-2026-54632 is a complete Denial of Service for active RTP or WebRTC media sessions utilizing vulnerable SIPSorcery instances. A single, small, unauthenticated malformed UDP packet is sufficient to terminate an ongoing session. There is no observed loss of confidentiality or integrity. While exposure is lower for blind off-path attackers who must first discover ephemeral ports, peer or on-path attackers can easily exploit this vulnerability. Organizations relying on SIPSorcery for VoIP, WebRTC, or other media communication could experience significant service disruptions, failed calls, and communication outages.

## Recommendation

* Upgrade the `SIPSorcery` NuGet package to version `10.0.9` or later immediately to patch CVE-2026-54632.
* As a temporary workaround for CVE-2026-54632, restrict access to the RTP/ICE port at the network layer to only known and trusted peers.

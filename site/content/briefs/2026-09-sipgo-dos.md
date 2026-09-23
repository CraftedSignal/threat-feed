---
title: Denial of Service via Unvalidated WebSocket Frame Length in sipgo
slug: 2026-09-sipgo-dos
description: An unauthenticated denial of service vulnerability in the sipgo WebSocket transport allows attackers to crash the service by sending a crafted frame with an oversized payload length field.
date: "2026-09-23T01:58:47Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:emiago:sipgo:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - sipgo
  - go
vendors:
  - emiago
products:
  - sipgo (<= 1.4.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated DoS. Any service using sipgo with a WS/WSS transport can be crashed by a single frame (panic).
    confidence_band: high
cves:
  - id: CVE-2026-77322
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-8h6x-h86x-75wh
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77322
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade sipgo to 1.4.3 or later
      owner: IT Operations
      due: 48h
      evidence: Source recommends setting MaxFrameSize which is addressed in the patched version.
  mitigation_plan:
    - priority: immediate
      action: 'Review server logs for Go runtime panics related to ''makeslice: len out of range'' following WebSocket connection establishment.'
      owner: SOC
      addresses: CVE-2026-77322
      evidence: Panic stack trace provided in PoC.
---

The Go-based SIP library `sipgo` (versions <= 1.4.2) contains a critical vulnerability in its WebSocket transport implementation, tracked as CVE-2026-77322. The `WSConnection.Read` function allocates a memory buffer based on the length field provided within a client-controlled WebSocket frame header without performing bounds validation. 

When `NextFrame()` is called, it initializes a `wsutil.NewReader` without enforcing a `MaxFrameSize` limit. An attacker can initiate a standard WebSocket handshake and subsequently transmit a single masked text frame with a payload length declared as an extremely high value (e.g., 2^63-1). This triggers a runtime panic due to an attempt to allocate an out-of-range slice, leading to an immediate crash of the entire server process. This vulnerability is particularly dangerous as it is unauthenticated, trivial to exploit, and requires only a single network packet to disrupt service availability.

## Attack Chain

1. Attacker establishes a WebSocket connection to the target server utilizing the `sipgo` library.
2. Attacker performs the standard WebSocket handshake process to establish the transport session.
3. Attacker constructs a malicious masked WebSocket text frame.
4. Attacker sets the frame header length marker to `127` to indicate an 8-byte length field.
5. Attacker sets the length value in the frame header to `0x7FFFFFFFFFFFFFFF` (2^63-1).
6. Server process calls `WSConnection.Read` and proceeds to allocate a slice based on the malicious header length.
7. Runtime environment throws a `makeslice: len out of range` panic, resulting in an unhandled crash of the server process.

## Impact

Successful exploitation results in an immediate, unauthenticated denial of service by crashing the host application. Services utilizing `sipgo` for SIP over WebSocket/WSS are susceptible to process termination, which can cause significant service disruption for telephony and communication infrastructure.

## Recommendation

Prioritized, concrete actions:

- Update the `sipgo` library to a version containing the fix for CVE-2026-77322, which enforces `MaxFrameSize` within `wsutil.NewReader`.
- Implement upstream network filtering or WAF policies to drop WebSocket traffic containing header-declared payload lengths exceeding the maximum expected message size for your specific SIP application.
- For detection, monitor server logs for recurring application panics or process restarts shortly following a WebSocket handshake, which may indicate active exploitation attempts.

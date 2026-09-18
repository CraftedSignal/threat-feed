---
title: Denial of Service Vulnerability in Netty StompSubframeDecoder
slug: 2026-09-netty-stomp-dos
description: A memory leak vulnerability in the Netty StompSubframeDecoder component (CVE-2026-93494) allows remote attackers to cause a Denial of Service by sending malformed STOMP frames.
date: "2026-09-18T12:05:00Z"
lastmod: "2026-09-18T16:07:09Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - netty
vendors:
  - Netty
products:
  - Netty
  - Netty (< 4.2.13.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote attacker can exploit this vulnerability by sending a specially crafted STOMP frame body without its terminating null byte, resulting in a Denial of Service.
    confidence_band: high
cves:
  - id: CVE-2026-93494
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93494
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93575
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications utilizing Netty for STOMP protocol communication
      owner: Application Security
      due: 48h
      evidence: Source advisory regarding Netty StompSubframeDecoder vulnerability
  mitigation_plan:
    - priority: immediate
      action: Patch Netty to the latest version as recommended by the project
      owner: IT Operations
      addresses: CVE-2026-93494
      evidence: Source identifies this as a fixable vulnerability
updates:
  - at: "2026-09-18T16:07:09Z"
    level: L1
    summary: added coverage for Netty (< 4.2.13.Final)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93575
---

A memory leak vulnerability (CVE-2026-93494) exists within the StompSubframeDecoder component of the Netty framework. The flaw is triggered when an attacker sends a STOMP frame body that lacks the expected terminating null byte. Upon receiving such a frame, the decoder performs a ByteBuf allocation that is never subsequently released by the application logic. Because the allocation persists in memory, repeated submission of these crafted frames leads to cumulative, uncontrolled memory consumption. This resource exhaustion eventually causes the host application to crash or become unresponsive, effectively resulting in a Denial of Service (DoS) for any services utilizing the affected STOMP codec. Defenders should prioritize identifying applications leveraging Netty for STOMP protocol handling to evaluate exposure and schedule patches.

## Impact

The vulnerability results in a Denial of Service for applications relying on the Netty StompSubframeDecoder. Persistent memory exhaustion can impact availability for any service exposed to untrusted STOMP traffic, potentially forcing service restarts or leading to total system instability if the memory limit is reached.

## Recommendation

- Identify all internal and customer-facing applications that utilize the Netty framework, specifically those incorporating the StompSubframeDecoder component.
- Review vendor release notes and security advisories for the Netty project to identify the specific patched version containing the fix for CVE-2026-93494.
- Apply the vendor-provided patch to all vulnerable Netty implementations.
- Monitor memory utilization metrics for services handling STOMP traffic to detect potential exploitation attempts causing memory pressure.

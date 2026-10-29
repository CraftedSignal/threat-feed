---
brief_id: brief-2026-10-29-twisted-telnet-dos
event_id: brief-2026-10-29-twisted-telnet-dos
revision: 1
activity_at: "2026-10-29T20:00:57Z"
title: 'Twisted: Memory exhaustion denial-of-service in Telnet implementation (CVE-2026-115778)'
slug: 2026-10-twisted-telnet-dos
description: An unauthenticated attacker can trigger a process-wide memory exhaustion denial-of-service in Twisted versions prior to 26.10.0rc1 by sending a specially crafted, unterminated Telnet subnegotiation sequence.
date: "2026-10-29T20:00:57Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source information regarding the buffer overflow is clear; no IOCs or specific logs provided, manual hunting required.
cpes:
  - cpe:2.3:a:twistedmatrix:twisted:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - python
  - telnet
  - memory-exhaustion
vendors:
  - Twisted Matrix Laboratories
products:
  - Twisted (< 26.10.0rc1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: The resulting memory exhaustion can terminate the process and every service it hosts.
    confidence_band: high
cves:
  - id: CVE-2026-115778
    cvss: 7.5
    epss: 0.0054
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115778
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify all internet-facing or internal services running the Twisted framework and audit version levels.
      owner: IT Operations
      due: 24h
      evidence: Twisted versions prior to 26.10.0rc1 are vulnerable.
  hunt_leads:
    - lead: Monitor for abnormally large Telnet payloads or repeated Telnet subnegotiation sequences (IAC SB) that lack the corresponding IAC SE terminator.
      technique_id: T1499.001
      data_needed:
        - Network traffic logs
        - Application-level Telnet session logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated peer can omit the terminator and continuously grow the buffer.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Twisted to 26.10.0rc1 or later.
      owner: IT Operations
      addresses: CVE-2026-115778
      evidence: This issue is fixed in version 26.10.0rc1.
---

Twisted versions prior to 26.10.0rc1 are vulnerable to a memory exhaustion denial-of-service attack. The vulnerability exists within `twisted.conch.telnet.Telnet.dataReceived`, which fails to enforce a maximum length on the subnegotiation buffer when processing data following an IAC SB (Interpret As Command Subnegotiation Begin) signal. Because this Telnet option negotiation occurs prior to authentication, an unauthenticated remote attacker can continuously send data bytes without the required IAC SE (Interpret As Command Subnegotiation End) terminator. This causes the buffer to grow until the application process exhausts memory and terminates, affecting all services hosted by that Twisted instance.

## Impact

Successful exploitation results in a process-wide crash, causing a denial-of-service for the affected application and all services managed by that specific Twisted process.

## Recommendation

* Upgrade Twisted to version 26.10.0rc1 or later immediately.
* If patching is not feasible, implement network-level controls to restrict access to services running the Twisted Telnet implementation to trusted IP ranges.
* Monitor network traffic directed at Twisted-based services for unusually long or high-frequency Telnet option negotiation sequences.

---
title: 'CVE-2026-85440: Heap Overflow in MOOS core-moos'
slug: 2026-09-moos-heap-overflow
description: A pre-authentication heap overflow vulnerability in the MOOSCommPkt packet handling of MOOS core-moos versions up to 10.4.0 allows remote unauthenticated attackers to perform arbitrary memory writes via crafted packets.
date: "2026-09-03T23:25:19Z"
lastmod: "2026-09-03T23:28:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:moos-ivp:core-moos:*:*:*:*:*:*:*:*
tags:
  - cve
  - authentication-bypass
  - middleware
  - denial-of-service
  - network-vulnerability
  - vulnerability
vendors:
  - MOOS-IvP
  - MOOS
products:
  - core-moos (<= 10.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MOOS core-moos through 10.4.0 contains a pre-authentication heap overflow vulnerability in MOOSCommPkt packet handling that allows remote attackers to write arbitrary data.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Authenticated attackers can forge message origins by supplying arbitrary source identifiers in serialized messages.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can send a crafted message with a negative length value to the MOOSDB port, causing an unhandled exception that terminates the database process.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An attacker can open a TCP connection to the MOOSDB port and send no data, causing the accept thread to block indefinitely while holding the socket-list lock.
    confidence_band: high
cves:
  - id: CVE-2026-85440
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85440
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85432
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85441
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85442
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85443
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all instances of core-moos to version 10.4.1 or later when available.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85440 advisory states vulnerability is present in versions through 10.4.0.
  mitigation_plan:
    - priority: immediate
      action: Restrict MOOS communication ports at the firewall level to authorized IP addresses.
      owner: IT Operations
      addresses: CVE-2026-85440
      evidence: Vulnerability is exploitable pre-authentication via remote network connection.
updates:
  - at: "2026-09-03T23:27:43Z"
    level: L2
    summary: added coverage for core-moos (<= 10.4.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85432
  - at: "2026-09-03T23:28:07Z"
    level: L1
    summary: added coverage for core-moos (<= 10.4.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85441
  - at: "2026-09-03T23:28:16Z"
    level: L1
    summary: added coverage for core-moos (<= 10.4.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85442
  - at: "2026-09-03T23:28:24Z"
    level: L1
    summary: added coverage for core-moos (<= 10.4.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85443
---

MOOS core-moos versions up to 10.4.0 contain a critical heap-based buffer overflow vulnerability within the MOOSCommPkt packet handling logic. The issue resides in the HandShake phase, which occurs before authentication is established. An unauthenticated remote attacker can supply a negative value in the packet length field, which bypasses existing signed integer checks within the InflateTo() function. This discrepancy leads to an improper size conversion when the data is passed to the recv() function, causing a heap overflow of a four-byte buffer. Successful exploitation allows an attacker to write arbitrary data into the process memory, potentially leading to remote code execution or application crashes. Given the pre-authentication nature of this flaw, defenders should prioritize patching or restricting access to the MOOS communication ports.

## Attack Chain

1. Attacker establishes a TCP/IP connection to the target host on the MOOS communication port.
2. Attacker initiates the HandShake phase of the communication protocol.
3. Attacker crafts a malicious packet header containing a negative integer in the packet length field.
4. The victim application receives the malicious packet via the InflateTo() function.
5. The vulnerability in the signed integer check allows the negative length to pass validation.
6. The application performs a heap-based memory allocation based on the unchecked length.
7. The recv() function processes the attacker-supplied data, resulting in a heap overflow of the internal four-byte buffer.
8. Attacker achieves arbitrary memory write, leading to remote code execution or process termination.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to execute arbitrary code or cause a denial-of-service condition on affected MOOS installations. This affects systems utilizing MOOS core-moos versions 10.4.0 and earlier. Organizations relying on this software for underwater vehicle communication or similar robotics research environments are at high risk if instances are exposed to untrusted networks.

## Recommendation

Prioritized, concrete actions:
- Patch core-moos by upgrading to a version exceeding 10.4.0 immediately upon release of vendor updates.
- Until patching is possible, restrict access to MOOS communication ports via host-based firewalls or network access control lists to known trusted endpoints only.
- Monitor network traffic for anomalous packet headers directed toward MOOS services, specifically looking for TCP streams containing negative length identifiers in the handshake phase.

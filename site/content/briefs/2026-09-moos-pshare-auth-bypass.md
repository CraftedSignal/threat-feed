---
title: Authentication Bypass and Message Injection in MOOS pShare
slug: 2026-09-moos-pshare-auth-bypass
description: The pShare component in MOOS essential-moos versions up to 10.0.1 is vulnerable to unauthenticated UDP message injection and denial-of-service.
date: "2026-09-03T23:24:40Z"
lastmod: "2026-09-04T01:24:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:moos-ivp:essential-moos:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-security
  - cve
  - authorization-bypass
  - robotics
vendors:
  - MOOS-IvP
products:
  - essential-moos (<= 10.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565.002
    technique_name: 'Data Manipulation: Stored Data Manipulation'
    evidence: Attackers can send crafted UDP datagrams to pShare input routes to inject messages into the local MOOS community under spoofed identities.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: Attackers can send crafted PSHARE_CMD messages with cmd=output or cmd=input parameters to open new listeners on arbitrary addresses and redirect or duplicate bus traffic to attacker-controlled destinations.
    confidence_band: high
cves:
  - id: CVE-2026-85430
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85430
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85433
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Implement network-level access control lists to restrict access to pShare UDP ports.
      owner: IT Operations
      due: 24h
      evidence: Source describes vulnerability as accepting UDP datagrams from any source.
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate all instances of MOOS essential-moos versions <= 10.0.1.
      owner: IT Operations
      addresses: CVE-2026-85430
      evidence: Source identifies vulnerability in versions through 10.0.1.
updates:
  - at: "2026-09-04T01:24:08Z"
    level: L2
    summary: added coverage for essential-moos (<= 10.0.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85433
---

MOOS-IvP essential-moos versions 10.0.1 and earlier contain a critical authentication bypass vulnerability within the pShare component. pShare is designed to share MOOS messages across different MOOS communities. The vulnerability arises because the process accepts UDP datagrams from any source without performing authentication or identity verification. An attacker on the local network can craft malicious UDP packets and inject arbitrary messages into the MOOS community while spoofing the identity of a legitimate MOOS process. Additionally, the lack of input validation allows an attacker to send malformed UDP datagrams that cause the pShare process to crash, resulting in a denial-of-service condition for the impacted MOOS community. This vulnerability is significant for environments relying on the integrity of MOOS-based communication in robotic and autonomous system fleets.

## Impact

Successful exploitation allows attackers to perform unauthorized message injection, potentially leading to the corruption of operational data or the execution of unauthorized commands within the MOOS community. Denial-of-service attacks against pShare can disrupt communication between critical mission components, rendering autonomous systems inoperable or uncontrollable.

## Recommendation

- Monitor network traffic for unexpected UDP communication directed at the port used by the pShare process.
- Implement network-level access control lists (ACLs) to restrict access to the pShare UDP port to trusted IP addresses only.
- Update all instances of MOOS-IvP essential-moos to a version that implements input validation and authentication for incoming UDP datagrams, if available.
- Audit logs for repeated service restarts or process crashes of the pShare binary, which may indicate attempted exploitation of the denial-of-service vulnerability.

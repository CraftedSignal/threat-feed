---
brief_id: brief-2026-09-15-dlink-buffer-overflow
event_id: brief-2026-09-15-dlink-buffer-overflow
revision: 2
activity_at: "2026-09-15T07:39:21Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:c2cb6e83d4a5a2bfdc1e544dd11a9527a76e4b2b18f06c09ea93c5299bd86bfc
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Remote Buffer Overflow Vulnerability in D-Link DI-8300
slug: 2026-09-15-dlink-buffer-overflow
description: A critical stack-based buffer overflow vulnerability in the D-Link DI-8300 CGI service enables remote code execution via a manipulated URL parameter.
date: "2026-09-15T07:39:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against NVD metadata
cpes:
  - cpe:2.3:h:dlink:di-8300:16.07:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve
  - network-infrastructure
vendors:
  - D-Link
products:
  - DI-8300 (16.07)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-91003
    cvss: 9.1
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91003
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to management interfaces of D-Link DI-8300 to trusted networks
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-91003 allows remote exploitation
  mitigation_plan:
    - priority: immediate
      action: Isolate affected D-Link DI-8300 devices from the internet
      owner: IT Operations
      addresses: CVE-2026-91003
      evidence: Public exploit availability
---

D-Link DI-8300 version 16.07 is affected by a stack-based buffer overflow vulnerability (CVE-2026-91003) residing within the CGI service component. The vulnerability is triggered through the 'rzgl_asp' function located in the '/rzgl.asp' endpoint. By providing a specially crafted input to the 'redirct_url' argument, an unauthenticated remote attacker can cause a buffer overflow, potentially leading to arbitrary code execution or a denial of service on the device. Proof-of-concept exploit code has been publicly released, increasing the risk of exploitation by opportunistic threat actors. Organizations utilizing this hardware must restrict access to management interfaces to trusted network segments or isolate the devices until a firmware resolution is provided by the vendor.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to execute arbitrary code with the privileges of the CGI service on the D-Link DI-8300 router. This could result in a full compromise of the device, enabling traffic interception, lateral movement into internal networks, or permanent denial of service. The vulnerability carries a CVSS v3.1 base score of 9.1, reflecting the severity of remote code execution on core network infrastructure.

## Recommendation

Prioritize the isolation of the D-Link DI-8300 management interface from the public internet. Ensure that network ingress to the device is restricted to trusted administrative IP addresses via firewall rules. Monitor internal logs for suspicious POST requests targeting '/rzgl.asp' with anomalous lengths in the 'redirct_url' parameter.

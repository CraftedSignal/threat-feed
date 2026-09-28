---
title: Remote Stack-based Buffer Overflow in Eyeplus p2pcam HTTP Parser
slug: 2026-09-eyeplus-overflow
description: A stack-based buffer overflow vulnerability in the p2pcam HTTP Parser component of Eyeplus 57.0.0.0308 allows remote attackers to execute arbitrary code via crafted HTTP requests.
date: "2026-09-28T06:47:04Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:eyeplus:p2pcam:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - buffer-overflow
vendors:
  - Eyeplus
products:
  - p2pcam (57.0.0.0308)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Such manipulation leads to stack-based buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-100908
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100908
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Isolate internet-facing p2pcam devices from direct public access
      owner: IT Operations
      due: 24h
      evidence: Remote exploitation is possible for this vulnerability
  mitigation_plan:
    - priority: immediate
      action: Identify and patch Eyeplus devices running 57.0.0.0308
      owner: IT Operations
      addresses: CVE-2026-100908
      evidence: NVD vulnerability disclosure
---

A stack-based buffer overflow vulnerability (CVE-2026-100908) has been identified in the p2pcam HTTP Parser component of Eyeplus version 57.0.0.0308. The vulnerability originates from improper bounds checking within an unknown function of the parser, allowing a remote attacker to trigger a buffer overflow condition. By sending a maliciously crafted HTTP request, an unauthorized remote actor can overwrite adjacent memory, potentially leading to arbitrary code execution on the target device. Publicly disclosed exploit code for this vulnerability is currently available, significantly lowering the barrier to entry for attackers. Given the nature of the p2pcam component, this risk is particularly acute for Internet-facing surveillance and camera hardware running the affected firmware version.

## Impact

Successful exploitation allows for unauthenticated remote code execution on the affected device, potentially leading to a complete compromise of the system, data exfiltration, or the recruitment of the device into a botnet. The severity is rated at 7.5 (CVSS v3.1), reflecting the potential for full system control by remote actors.

## Recommendation

- Identify all internet-facing devices running Eyeplus firmware version 57.0.0.0308.
- Restrict network access to the p2pcam HTTP interface to trusted internal segments only, as this is a remote-exploitable vulnerability.
- Contact the vendor for a security patch or firmware update addressing CVE-2026-100908.
- Monitor ingress traffic on ports associated with the p2pcam web interface for anomalous HTTP payloads, specifically looking for abnormally long URI strings or unexpected character sequences.

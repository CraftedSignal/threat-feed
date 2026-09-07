---
title: Critical RCE Vulnerability in N-able N-central
slug: 2026-09-n-central-rce
description: A critical unauthenticated remote code execution vulnerability (CVE-2026-86218) in N-able N-central is under active exploitation, allowing attackers to gain full system control.
date: "2026-09-07T12:55:57Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:n_able:n_central:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - critical
  - remote-management
vendors:
  - N-able
products:
  - N-central (< 2026.3.1.14)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability makes it possible for unauthorized individuals to execute harmful code remotely without login credentials.
    confidence_band: high
cves:
  - id: CVE-2026-86218
    epss: 0.00411
references:
  - https://www.ncsc.nl/alerts/kwetsbaarheid-in-n-central-van-n-able-update-nu
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade on-premises N-central to 2026.3.1.14 or later
      owner: IT Operations
      due: 24h
      evidence: N-able has released an update that solves this vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Patch N-central to 2026.3.1.14
      owner: IT Operations
      addresses: CVE-2026-86218
      evidence: All versions of N-central older than 2026.3.1.14 are vulnerable.
---

N-able has identified a critical vulnerability, CVE-2026-86218, affecting its N-central remote monitoring and management platform. This vulnerability carries a CVSS score of 10 and permits unauthenticated, remote attackers to execute arbitrary code on the underlying system. The flaw is currently being exploited in the wild, posing an immediate risk to IT service providers and organizations managing IT systems via this software. N-central is frequently used by IT service providers, making it a high-value target for attackers aiming to pivot into the downstream environments of managed clients. All on-premises instances prior to version 2026.3.1.14 are susceptible to compromise, which results in full system take-over. Hosted N-able N-central (NCOD) instances have been patched by the vendor.

## Impact

Successful exploitation of CVE-2026-86218 results in total system compromise. Given N-central's role as a central management platform, the impact includes potential massive data exfiltration, service disruption, and the ability for attackers to distribute secondary malware or ransomware across the entire managed infrastructure of the victim organization and their clients. The vulnerability is currently being actively exploited, necessitating immediate remediation for all on-premises deployments.

## Recommendation

* Prioritize the immediate upgrade of all on-premises N-central instances to version 2026.3.1.14 or later to mitigate CVE-2026-86218.
* Monitor web server and application access logs for anomalous, unauthenticated POST requests or unusual execution patterns targeting N-central management ports.
* Verify with N-able support or your IT service provider if you are currently running an on-premises version of the software.
* Deploy endpoint detection and response (EDR) solutions on the servers hosting N-central to detect unauthorized process creation or command execution originating from the web application process.

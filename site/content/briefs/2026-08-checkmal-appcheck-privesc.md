---
title: Local Privilege Escalation in CheckMAL AppCheck Pro via Kernel Driver
slug: 2026-08-checkmal-appcheck-privesc
description: A local privilege escalation vulnerability in the AppCheckD.sys driver of CheckMAL AppCheck Pro version 3.1.43.10 allows attackers to perform uncontrolled search path manipulation.
date: "2026-08-03T18:05:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - kernel-driver
vendors:
  - CheckMAL
products:
  - AppCheck Pro (3.1.43.10)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Performing a manipulation results in uncontrolled search path.
    confidence_band: high
cves:
  - id: CVE-2026-18605
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18605
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory affected AppCheck Pro installations.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-18605 identified in AppCheck Pro 3.1.43.10.
  mitigation_plan:
    - priority: short_term
      action: Restrict local non-admin access to machines running the vulnerable driver.
      owner: IT Operations
      addresses: CVE-2026-18605
      evidence: Attack requires a local approach.
---

A security vulnerability has been identified in CheckMAL AppCheck Pro version 3.1.43.10 involving an unknown function within the AppCheckD.sys kernel mini-filter driver. This flaw enables an attacker with local access to conduct an uncontrolled search path manipulation, potentially leading to unauthorized privilege escalation. While the vulnerability is reported as complex to exploit, a public exploit exists, increasing the risk for environments where this security software is deployed. CheckMAL has reportedly remained unresponsive to disclosure attempts, leaving the vulnerability unpatched in the specified version. Security teams should assess the presence of AppCheck Pro in their environment and monitor for local activities involving the driver.

## Impact

Successful exploitation of this vulnerability allows a local attacker to execute arbitrary code with kernel-level privileges. This facilitates a complete compromise of the affected host, enabling persistence, data exfiltration, and bypass of installed security controls. Given the nature of the software as a security product, its compromise undermines the integrity of the host's defensive posture.

## Recommendation

1. Inventory all endpoints running CheckMAL AppCheck Pro 3.1.43.10 to identify exposure.
2. Restrict non-administrator local access to systems running this software to mitigate the local exploit vector.
3. Monitor for unusual process execution or file modifications involving the AppCheckD.sys driver or associated application directories.
4. Consider alternative security solutions if the vendor continues to provide no patch for this critical-impact driver vulnerability.

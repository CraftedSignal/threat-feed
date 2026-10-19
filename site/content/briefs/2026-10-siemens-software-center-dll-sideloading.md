---
title: Active Exploitation of CVE-2026-110936 in Siemens Software Center
slug: 2026-10-siemens-software-center-dll-sideloading
description: Siemens Software Center versions prior to 4.0.9.8 are vulnerable to a DLL sideloading attack identified as CVE-2026-110936, which is currently being exploited in the wild to achieve arbitrary code execution.
date: "2026-10-19T22:22:27Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:siemens:software_center:*:*:*:*:*:*:*:*
tags:
  - dll-sideloading
  - vulnerability
  - cve
vendors:
  - Siemens
products:
  - Siemens Software Center (< V4.0.9.8)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: Siemens has reported that CVE-2026-110936 is being exploited in the wild.
    confidence_band: high
cves:
  - id: CVE-2026-110936
    cvss: 6.7
    epss: 0.00135
references:
  - https://cyber.gc.ca/en/alerts-advisories/siemens-security-advisory-av26-1063
  - https://productcert.siemens.com/productcert/html/ssa-580366.html
  - https://productcert.siemens.com/news/2026/10/19/active-exploitation-of-cve-2026-110936-in-siemens-software-center/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Siemens Software Center to V4.0.9.8 or later
      owner: IT Operations
      due: 24h
      evidence: Siemens Software Center < V4.0.9.8 is affected by CVE-2026-110936
  mitigation_plan:
    - priority: immediate
      action: Upgrade Siemens Software Center to V4.0.9.8
      owner: IT Operations
      addresses: CVE-2026-110936
      evidence: Siemens security advisory SSA-580366
---

Siemens has released a security advisory regarding a high-severity DLL sideloading vulnerability in the Siemens Software Center (CVE-2026-110936). The vulnerability, which affects all versions prior to V4.0.9.8, allows unprivileged attackers to execute arbitrary code with the privileges of the target application. Siemens has confirmed that this vulnerability is currently being exploited in the wild. This flaw arises because the application improperly validates or specifies the search path for required dynamic link libraries (DLLs), enabling attackers to plant a malicious library in a directory where the application will prioritize it for loading over the legitimate system-provided file. This technique is a common method for achieving persistence and executing malicious payloads while evading traditional signature-based detection. Organizations using Siemens Software Center are urged to update to V4.0.9.8 or later immediately.

## Impact

Successful exploitation of CVE-2026-110936 leads to arbitrary code execution on the host machine running Siemens Software Center. Given the nature of the application, this may allow an attacker to gain elevated privileges or maintain persistent access to the internal network. The vulnerability is being actively exploited, increasing the risk for all organizations currently running vulnerable versions of this software.

## Recommendation

1. Upgrade all instances of Siemens Software Center to version 4.0.9.8 or later immediately to mitigate the underlying vulnerability CVE-2026-110936.
2. Audit environment for unexpected DLL files located in the installation directory of Siemens Software Center.
3. Implement endpoint monitoring for file creation events within application directories to identify unauthorized file placement.

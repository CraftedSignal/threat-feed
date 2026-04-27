---
title: 'CVE-2026-33100: Windows WinSock Use-After-Free Privilege Escalation'
slug: 2026-04-winsock-uaf
description: CVE-2026-33100 is a use-after-free vulnerability in the Windows Ancillary Function Driver for WinSock, allowing a locally authorized attacker to elevate privileges.
date: "2026-04-14T18:17:32Z"
severities:
  - high
tags:
  - cve-2026-33100
  - use-after-free
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-33100
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33100
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33100
rules:
  - title: Suspicious Process Creation via WinSock Exploit
    description: Detects suspicious processes potentially spawned as a result of exploiting the WinSock use-after-free vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Detecting potentially malformed Winsock API calls
    description: This rule detects anomalic process start events which could indicate exploitation of Winsock.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-33100 is a use-after-free vulnerability present within the Windows Ancillary Function Driver for WinSock. This flaw enables an attacker with local access and a degree of authorization to escalate their privileges on the system. The vulnerability stems from improper memory management within the WinSock driver, leading to potential access of freed memory. Exploitation of this vulnerability would allow an attacker to execute arbitrary code with elevated privileges. Microsoft has…

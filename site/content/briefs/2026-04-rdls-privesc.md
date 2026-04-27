---
title: Windows Remote Desktop Licensing Service Privilege Escalation Vulnerability (CVE-2026-26160)
slug: 2026-04-rdls-privesc
description: CVE-2026-26160 is a privilege escalation vulnerability in the Windows Remote Desktop Licensing Service due to missing authentication, allowing a local attacker to gain elevated privileges.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - privilege escalation
  - rdls
  - cve-2026-26160
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26160
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26160
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26160
rules:
  - title: Suspicious Process interacting with Remote Desktop Licensing Service
    description: Detects suspicious processes interacting with the Remote Desktop Licensing Service, potentially indicating exploitation of CVE-2026-26160.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Remote Desktop Licensing Service Crash
    description: Detects events indicating a crash or abnormal termination of the Remote Desktop Licensing Service, which could be a result of exploiting CVE-2026-26160.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - system
      - windows
rules_count: 2
---

CVE-2026-26160 is a critical vulnerability affecting the Windows Remote Desktop Licensing Service (RDLS). This vulnerability stems from a missing authentication check for a critical function within the service. A locally authenticated attacker can exploit this flaw to elevate their privileges on the system. The vulnerability was publicly disclosed on April 14, 2026. The scope of the vulnerability is limited to local privilege escalation, meaning an attacker needs existing access to the system…

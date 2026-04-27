---
title: Windows Remote Desktop Licensing Service Privilege Escalation via CVE-2026-26159
slug: 2026-04-rdls-privesc
description: CVE-2026-26159 allows a local attacker to escalate privileges on Windows systems due to a missing authentication check in the Remote Desktop Licensing Service (RDLS).
date: "2026-04-14T18:16:48Z"
severities:
  - high
tags:
  - cve-2026-26159
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26159
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26159
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26159
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious RDLS Process Creation
    description: Detects suspicious process creation events related to the Remote Desktop Licensing Service that may indicate exploitation of CVE-2026-26159.
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
  - title: Detect System Configuration Modification by RDLS
    description: Detects attempts to modify system configurations by RDLS, which may indicate an attempt to exploit CVE-2026-26159 for privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

CVE-2026-26159 is a privilege escalation vulnerability affecting the Windows Remote Desktop Licensing Service (RDLS). The vulnerability stems from a missing authentication check for a critical function within the service. An attacker with local access to a vulnerable system can exploit this flaw to elevate their privileges to SYSTEM. The vulnerability was reported to Microsoft and assigned a CVSS v3.1 score of 7.8 (HIGH). Successful exploitation allows an attacker to perform actions with…

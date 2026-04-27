---
title: 'CVE-2026-27910: Windows Installer Local Privilege Escalation'
slug: 2026-04-windows-installer-privilege-escalation
description: CVE-2026-27910 describes a local privilege escalation vulnerability in Windows Installer due to improper handling of insufficient permissions, allowing an authorized attacker to gain elevated privileges.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - cve-2026-27910
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27910
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27910
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27910
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Suspicious MSIEXEC Execution
    description: Detects suspicious execution of msiexec.exe with command-line arguments indicative of potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Registry Modification Detection
    description: Detects modifications to critical registry keys often targeted during privilege escalation attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

CVE-2026-27910 is a vulnerability within Windows Installer that stems from the improper handling of insufficient permissions or privileges. This flaw enables an attacker with local access and some level of authorization to elevate their privileges on the system. The vulnerability, reported on April 14, 2026, could be exploited by a malicious actor to gain administrative rights, potentially leading to unauthorized data access, system modification, or complete system compromise. The affected…

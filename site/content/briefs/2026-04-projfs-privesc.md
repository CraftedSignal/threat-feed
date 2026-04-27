---
title: Windows Projected File System Buffer Over-Read Privilege Escalation (CVE-2026-26184)
slug: 2026-04-projfs-privesc
description: CVE-2026-26184 is a buffer over-read vulnerability in the Windows Projected File System (ProjFS) that allows a local attacker to elevate privileges.
date: "2026-04-14T18:16:55Z"
severities:
  - high
tags:
  - cve-2026-26184
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26184
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26184
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26184
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious ProjFS Activity
    description: Detects potential exploitation attempts of CVE-2026-26184 by monitoring for unusual activity related to the ProjFS driver.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect Potential Privilege Escalation via ProjFS
    description: Detects potential privilege escalation attempts related to ProjFS by monitoring for unusual process creations or kernel module loads after ProjFS activity.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-26184 is a high-severity vulnerability affecting the Windows Projected File System (ProjFS). This buffer over-read vulnerability allows an authenticated local attacker to elevate their privileges on a vulnerable system. Successful exploitation would grant the attacker higher-level access to the system, potentially enabling them to perform actions such as installing programs, viewing, changing, or deleting data, or creating new accounts with full user rights. The vulnerability was…

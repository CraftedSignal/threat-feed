---
title: Microsoft Management Console Improper Access Control Vulnerability (CVE-2026-27914)
slug: 2026-04-mmc-privesc
description: CVE-2026-27914 is an improper access control vulnerability in Microsoft Management Console that allows a locally authorized attacker to elevate privileges.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - cve-2026-27914
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27914
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27914
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27914
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious MMC Command Line Arguments
    description: Detects suspicious command line arguments used with mmc.exe which may indicate exploitation of privilege escalation vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect MMC spawning suspicious child processes
    description: Detects instances of MMC spawning child processes that are typically associated with malicious activity or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-27914 describes an improper access control vulnerability affecting Microsoft Management Console (MMC). The vulnerability allows an attacker who already has local access to a system, but with limited privileges, to elevate those privileges to a higher level. This could allow the attacker to perform actions they would normally be restricted from doing, potentially leading to full system compromise. Public details emerged on April 14, 2026 when the CVE was published by Microsoft…

---
title: Windows Server Update Service (WSUS) Privilege Escalation via CVE-2026-26174
slug: 2026-04-wsus-privesc
description: CVE-2026-26174 is a race condition vulnerability in Windows Server Update Service that allows an authorized attacker to elevate privileges locally.
date: "2026-04-14T18:23:14Z"
severities:
  - high
tags:
  - cve-2026-26174
  - privilege-escalation
  - windows
  - wsus
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26174
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26174
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26174
ioc_counts:
  email: 2
rules:
  - title: Detect Suspicious WSUS Child Processes
    description: Detects unusual child processes spawned by the WSUS process (w3wp.exe), which could indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect WSUS File Modifications
    description: Detects modifications to files within the WSUS installation directory, which could indicate an attempted exploit.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-26174 describes a race condition vulnerability within the Windows Server Update Service (WSUS). Disclosed on April 14, 2026, this flaw allows a locally authenticated attacker with limited privileges to elevate their privileges to SYSTEM. The vulnerability stems from improper synchronization when WSUS handles concurrent requests, leading to a race condition that can be exploited to overwrite critical system files or manipulate system processes. Successful exploitation could grant an…

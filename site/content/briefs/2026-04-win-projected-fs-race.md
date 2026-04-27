---
title: Windows Projected File System Race Condition Privilege Escalation (CVE-2026-27927)
slug: 2026-04-win-projected-fs-race
description: CVE-2026-27927 is a race condition vulnerability in the Windows Projected File System that allows an authorized attacker to escalate privileges locally.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - race-condition
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27927
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27927
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-27927
rules:
  - title: Detect Suspicious ProjFS Process Execution
    description: Detects suspicious process executions potentially related to exploiting CVE-2026-27927
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious File Operations in Projected File System
    description: Detects unusual file operations that may indicate exploitation of CVE-2026-27927
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-27927 describes a race condition vulnerability within the Windows Projected File System (ProjFS). This vulnerability allows a locally authenticated attacker to elevate their privileges. The vulnerability exists due to improper synchronization when multiple threads or processes access shared resources within ProjFS concurrently. An attacker can exploit this by manipulating the timing of operations to gain unauthorized access or control. The vulnerability was published on April 14, 2026…

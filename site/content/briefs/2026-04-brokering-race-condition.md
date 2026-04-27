---
title: Microsoft Brokering File System Race Condition Vulnerability (CVE-2026-32091)
slug: 2026-04-brokering-race-condition
description: CVE-2026-32091 is a race condition vulnerability in the Microsoft Brokering File System, allowing an unauthenticated local attacker to escalate privileges.
date: "2026-04-14T18:17:14Z"
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
  - id: CVE-2026-32091
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32091
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32091
rules:
  - title: Detect Suspicious Brokering File System Privilege Escalation
    description: Detects potential privilege escalation attempts exploiting a race condition in the Microsoft Brokering File System.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Concurrent Access to Shared Resource
    description: Detects concurrent access using shared resource, looking for potential race condition exploitation.
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

CVE-2026-32091 is a critical vulnerability affecting the Microsoft Brokering File System. The vulnerability is due to a race condition that occurs during concurrent execution while accessing a shared resource without proper synchronization. A local, unauthenticated attacker can exploit this flaw to elevate their privileges on the system. This vulnerability, if successfully exploited, could allow an attacker to perform actions with elevated permissions, potentially leading to full system…

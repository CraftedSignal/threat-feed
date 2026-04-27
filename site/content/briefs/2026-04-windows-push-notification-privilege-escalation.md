---
title: Windows Push Notifications Race Condition Privilege Escalation (CVE-2026-32160)
slug: 2026-04-windows-push-notification-privilege-escalation
description: CVE-2026-32160 describes a race condition vulnerability in Windows Push Notifications that allows a locally authorized attacker to elevate privileges.
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
  - id: CVE-2026-32160
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32160
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32160
rules:
  - title: Suspicious Process Spawned by Windows Push Notifications Service
    description: Detects potential exploitation of CVE-2026-32160 by monitoring for unusual child processes spawned by the Windows Push Notifications service.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Potential CVE-2026-32160 Exploit - File Creation in System32 by svchost
    description: Detects potential exploitation by monitoring file creation events in System32 initiated by svchost.exe (Windows Push Notifications service).
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-32160 is a vulnerability affecting Windows Push Notifications. Discovered and reported by Microsoft, it stems from a race condition that occurs during concurrent execution using a shared resource without proper synchronization. This flaw enables a local attacker with authorization to elevate their privileges on the affected system. The vulnerability was published on April 14, 2026, and is documented in the NVD database. Exploitation requires local access, but successful exploitation…

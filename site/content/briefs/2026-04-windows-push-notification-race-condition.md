---
title: Windows Push Notifications Race Condition Privilege Escalation (CVE-2026-32159)
slug: 2026-04-windows-push-notification-race-condition
description: CVE-2026-32159 is a race condition vulnerability in Windows Push Notifications, allowing a local attacker with low privileges to elevate privileges by exploiting concurrent execution using a shared resource with improper synchronization.
date: "2026-04-14T18:17:17Z"
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
  - id: CVE-2026-32159
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32159
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32159
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Push Notification Processes
    description: Detects suspicious processes interacting with Windows Push Notifications, potentially indicating an exploit attempt of CVE-2026-32159
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential Privilege Escalation via Process Spawn
    description: Detects processes spawned by system processes, which can indicate privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32159 is a critical vulnerability affecting Windows Push Notifications, stemming from a race condition during concurrent execution involving shared resources. This flaw allows a locally authenticated attacker with low privileges to escalate their privileges to a higher level on the system. The vulnerability arises because of improper synchronization, leading to unpredictable behavior when multiple threads access the same resource simultaneously. Successful exploitation grants the…

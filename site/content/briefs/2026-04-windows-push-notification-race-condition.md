---
title: Windows Push Notifications Race Condition Privilege Escalation (CVE-2026-32159)
slug: 2026-04-windows-push-notification-race-condition
description: CVE-2026-32159 is a race condition vulnerability in Windows Push Notifications, allowing a local attacker with low privileges to elevate privileges by exploiting concurrent execution using a shared resource with improper synchronization.
date: "2026-04-14T18:17:17Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: email
    value: '[email&#160;protected]'
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

CVE-2026-32159 is a critical vulnerability affecting Windows Push Notifications, stemming from a race condition during concurrent execution involving shared resources. This flaw allows a locally authenticated attacker with low privileges to escalate their privileges to a higher level on the system. The vulnerability arises because of improper synchronization, leading to unpredictable behavior when multiple threads access the same resource simultaneously. Successful exploitation grants the attacker elevated control over the compromised system. The vulnerability was reported on April 14, 2026, and is documented by Microsoft and the National Vulnerability Database (NVD).

## Attack Chain

1.  Attacker gains initial access to the Windows system with low-privileged credentials.
2.  Attacker crafts a malicious application designed to interact with Windows Push Notifications.
3.  The malicious application initiates multiple concurrent requests to a shared resource within the Windows Push Notifications service.
4.  Due to the race condition (CWE-362), the concurrent requests cause improper synchronization when accessing the shared resource.
5.  The attacker manipulates the timing of the requests to exploit the race condition.
6.  The successful exploitation overwrites critical data structures with attacker-controlled values.
7.  The attacker escalates their privileges to gain SYSTEM-level access.
8.  With elevated privileges, the attacker can perform unauthorized actions such as installing software, modifying system settings, or accessing sensitive data.

## Impact

A successful exploit of CVE-2026-32159 allows a local attacker to elevate their privileges from a low-privileged account to SYSTEM, granting them full control over the affected Windows system. This could lead to complete system compromise, data theft, or deployment of malware. While the vulnerability requires local access, it can be combined with other vulnerabilities or social engineering techniques to gain initial access. The vulnerability has a CVSS v3.1 score of 7.8, indicating a high severity.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-32159 on all affected Windows systems (reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32159).
*   Monitor process creation events for suspicious processes interacting with Windows Push Notifications services to identify potential exploit attempts.
*   Deploy the Sigma rule `DetectSuspiciousPushNotificationProcesses` to detect potentially malicious processes interacting with the Windows Push Notification service.

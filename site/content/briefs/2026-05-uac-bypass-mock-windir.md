---
title: UAC Bypass Attempt via Windows Directory Masquerading
slug: 2026-05-uac-bypass-mock-windir
description: Detects attempts to bypass User Account Control (UAC) by masquerading as a trusted Microsoft Windows directory, abusing a trailing-space in the path to execute code with elevated privileges.
date: "2026-05-12T19:10:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - uac-bypass
  - windows
vendors:
  - Microsoft
  - Elastic
  - CrowdStrike
  - SentinelOne
products:
  - Elastic Endpoint
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Crowdstrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e
rules:
  - title: Detect UAC Bypass via Mock Windows Directory
    description: Detects UAC bypass attempts by identifying processes executed from a Windows directory path with a trailing space.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.002
    data_sources:
      - process_creation
      - windows
  - title: Detect UAC Bypass via Copied Binary in Mock Windows Directory
    description: Detects UAC bypass attempts by identifying copied, auto-elevating binaries running from a Windows directory path with a trailing space.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies attempts to bypass User Account Control (UAC) by masquerading as a Microsoft trusted Windows directory. Attackers may bypass UAC to stealthily execute code with elevated permissions. This technique abuses a trailing-space "C:\\Windows " tree that AppInfo checks can normalize while the fake path still executes. The rule focuses on identifying processes running from paths that mimic the Windows directory structure but include a trailing space, a common tactic used to circumvent UAC restrictions. This allows execution of unauthorized code with elevated privileges.

## Attack Chain

1.  Attacker gains initial access to the system through a separate vector (e.g., phishing, exploit).
2.  Attacker creates a directory mimicking a trusted Windows directory, but with a trailing space (e.g., `C:\\Windows \\System32`).
3.  Attacker copies a legitimate, auto-elevating Windows executable (e.g., `eventvwr.exe`) to the newly created directory.
4.  Attacker executes the copied executable from the mock directory. The system may normalize the path due to the trailing space, but the executable still runs.
5.  The executed process bypasses UAC checks due to the apparent trusted location.
6.  The process spawns a new process with elevated privileges.
7.  Attacker performs malicious actions with the elevated privileges, such as installing malware or modifying system settings.
8.  Attacker cleans up the mock directory and copied executable to remove traces of the attack.

## Impact

A successful UAC bypass allows an attacker to execute arbitrary code with elevated privileges, potentially leading to full system compromise. This can result in data theft, malware installation, or complete system takeover. While the specific number of affected systems is not detailed in the source, the technique is broadly applicable to any Windows system where the attacker has achieved initial access.

## Recommendation

*   Deploy the Sigma rule `Detect UAC Bypass via Mock Windows Directory` to your SIEM and tune for your environment to detect the creation of processes with a trailing space in the path.
*   Enable Sysmon process creation logging to capture the necessary process execution events for the Sigma rules to function effectively.
*   Implement file integrity monitoring on critical Windows directories to detect unauthorized file modifications, as described in the "File events for the suspicious process" investigation transform.
*   Review and restrict the execution of binaries from user-writable or fake trusted paths, as mentioned in the post-incident hardening steps.
*   Investigate alerts triggered by the `UAC Bypass Attempt via Windows Directory Masquerading` rule in Elastic to determine if a mock trusted Windows directory was used.

---
title: Potential Windows Session Hijacking via CcmExec
slug: 2024-07-sccm-dll-hijacking
description: Adversaries may exploit Microsoft's System Center Configuration Manager by loading malicious DLLs into SCNotification.exe, a process associated with user notifications, potentially leading to Windows session hijacking.
date: "2024-07-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - dll-hijacking
  - sccm
vendors:
  - Microsoft
products:
  - System Center Configuration Manager
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/windows-session-hijacking-via-ccmexec
  - https://mayfly277.github.io/posts/SCCM-LAB-part0x3/#impersonate-users---revshell-connected-users
rules:
  - title: Potential Windows Session Hijacking via CcmExec
    description: Detects when 'SCNotification.exe' loads an untrusted DLL, which is a potential indicator of an attacker attempt to hijack/impersonate a Windows user session.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - windows
  - title: Suspicious DLL Load by SCNotification.exe with Short Creation Time
    description: Detects SCNotification.exe loading a recently created DLL, indicating potential DLL hijacking.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers may attempt to hijack Windows user sessions by exploiting Microsoft's System Center Configuration Manager (SCCM). This involves loading malicious DLLs into `SCNotification.exe`, a process responsible for user notifications within the SCCM framework. The vulnerability arises when `SCNotification.exe` loads untrusted DLLs, potentially impersonating a user session. This activity is often characterized by recent DLL file creation or modification, coupled with the DLL lacking a trusted code signature. The references indicate this technique has been discussed publicly, raising awareness and the potential for increased exploitation.

## Attack Chain

1.  Attacker gains initial access to the target system.
2.  Attacker places a malicious DLL on the system. This DLL may be disguised to appear legitimate.
3.  The attacker manipulates the system to cause `SCNotification.exe` to load the malicious DLL. This may involve modifying registry keys or file paths.
4.  `SCNotification.exe` loads the attacker-controlled DLL.
5.  The malicious DLL executes within the context of the `SCNotification.exe` process.
6.  The attacker leverages the hijacked process to impersonate a user session.
7.  Attacker gains unauthorized access to user accounts and data.
8.  Attacker performs malicious actions under the guise of the compromised user, such as data exfiltration or privilege escalation.

## Impact

A successful attack could lead to unauthorized access to sensitive data, privilege escalation, and further compromise of the network. Victims could experience data breaches, financial loss, or reputational damage. The impact depends on the extent of access gained by the attacker and the sensitivity of the data accessed.

## Recommendation

*   Deploy the Sigma rule "Potential Windows Session Hijacking via CcmExec" to your SIEM to detect suspicious DLL loads by `SCNotification.exe`.
*   Investigate alerts triggered by the Sigma rule, focusing on DLLs with recent file creation times or modifications (DLL timestamps) and untrusted signatures.
*   Implement application whitelisting to prevent unauthorized DLLs from being loaded by `SCNotification.exe` as described in the remediation steps in the note section.
*   Monitor process creation events for `SCNotification.exe` and related processes.
*   Enable Sysmon process creation logging to enhance visibility into process execution events, which activates the Sigma rules above.

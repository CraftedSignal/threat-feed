---
title: Potential Modification of Accessibility Binaries for Persistence
slug: 2026-05-accessibility-binary-modification
description: Adversaries may modify or replace Windows accessibility binaries (e.g., sethc.exe, utilman.exe) to execute malicious commands or establish persistence mechanisms before a user logs in, potentially leading to elevated privileges and unauthorized access.
date: "2026-05-12T18:39:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege_escalation
  - accessibility_features
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://www.elastic.co/blog/practical-security-engineering-stateful-detection
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/008/
rules:
  - title: Detect Accessibility Binary Replacement via Original Filename
    description: Detects the replacement of accessibility binaries by monitoring process creations where the original filename does not match the expected executable name but is spawned by utilman.exe or winlogon.exe as SYSTEM.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.008
    data_sources:
      - process_creation
      - windows
  - title: Detect Accessibility Binary launched from unexpected path
    description: Detects accessibility binaries launched from unusual paths, indicating potential hijacking.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.008
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Windows accessibility features, such as Narrator, Magnifier, and On-Screen Keyboard, are designed to assist users with disabilities and can be launched from the login screen using specific key combinations. Attackers can abuse this functionality by replacing legitimate accessibility binaries with malicious executables, allowing them to execute arbitrary commands with SYSTEM privileges before a user logs in. This technique is often used for persistence, privilege escalation, and establishing backdoors. The detection focuses on identifying processes launched by accessibility features with unexpected original file names, which may indicate malicious replacement or modification. Successful exploitation allows an attacker to bypass standard login procedures and gain unauthorized access to the system with elevated privileges.

## Attack Chain

1.  An attacker gains initial access to the system (e.g., via compromised credentials or remote access).
2.  The attacker identifies the accessibility binaries (e.g., `C:\\Windows\\System32\\sethc.exe`, `C:\\Windows\\System32\\utilman.exe`).
3.  The attacker replaces a legitimate accessibility binary with a malicious executable (e.g., a reverse shell or command interpreter) using tools like `takeown` and `icacls` to modify file permissions.
4.  The attacker configures the system to launch the malicious executable when the corresponding accessibility feature is invoked from the login screen.
5.  The system is rebooted or locked, presenting the login screen.
6.  The attacker invokes the replaced accessibility feature using the associated key combination (e.g., pressing Shift five times for Sticky Keys/sethc.exe).
7.  The malicious executable is launched with SYSTEM privileges, providing the attacker with a command prompt or remote access shell.
8.  The attacker performs malicious actions, such as creating new accounts, installing malware, or exfiltrating data.

## Impact

Successful exploitation of this technique allows attackers to gain persistent, elevated access to the compromised system. The attacker can bypass normal login procedures and execute commands with SYSTEM privileges. This can lead to complete system compromise, data theft, and the installation of persistent backdoors. The scope can range from a single workstation to multiple systems within an organization if the attacker is able to automate the replacement process.

## Recommendation

*   Deploy the "Potential Modification of Accessibility Binaries" Sigma rule to your SIEM to detect unauthorized modifications of accessibility binaries.
*   Enable Sysmon process-creation logging to provide the necessary data for the Sigma rule.
*   Monitor for processes spawned by `Utilman.exe` or `winlogon.exe` with a user context of "SYSTEM" and an unexpected `process.pe.original_file_name` as defined in the Sigma rule.
*   Implement strict file permission controls on accessibility binaries in `C:\\Windows\\System32\\` to prevent unauthorized modification.
*   Regularly audit and verify the integrity of accessibility binaries to detect any unauthorized changes.

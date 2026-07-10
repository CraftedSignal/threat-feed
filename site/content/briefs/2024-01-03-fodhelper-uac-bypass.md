---
title: FodHelper UAC Bypass Attempt
slug: 2024-01-03-fodhelper-uac-bypass
description: Detection of fodhelper.exe execution, which is known to exploit User Account Control (UAC) bypass by leveraging specific registry keys, potentially leading to privilege escalation.
date: "2024-01-03T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - uac-bypass
  - privilege-escalation
  - fodhelper
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md
  - https://github.com/gushmazuko/WinBypass/blob/master/FodhelperBypass.ps1
  - https://attack.mitre.org/techniques/T1548/002/
rules:
  - title: Fodhelper UAC Bypass - Process Creation
    description: Detects the execution of processes spawned by fodhelper.exe, indicating a potential UAC bypass.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1548.002
    data_sources:
      - process_creation
      - windows
  - title: Fodhelper UAC Bypass - Registry Modification
    description: Detects modification of specific registry keys commonly used in Fodhelper UAC bypass attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1112
      - T1548.002
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The fodhelper.exe is a legitimate Windows program located in `C:\Windows\System32\`. However, it can be abused to bypass User Account Control (UAC) due to its auto-elevated status. When executed, fodhelper.exe can be manipulated to execute arbitrary commands with elevated privileges by modifying specific registry keys. This technique is often employed by threat actors to escalate privileges and perform malicious activities. This behavior is significant because it allows attackers to bypass security controls and gain unauthorized access to the system with administrative rights. This technique has been observed in conjunction with malware such as IcedID, ValleyRAT, and BlankGrabber Stealer.

## Attack Chain

1. An attacker gains initial access to the system, often through phishing or other social engineering techniques.
2. The attacker executes a script or program that attempts to exploit the Fodhelper UAC bypass.
3. The malicious script modifies specific registry keys under `HKCU\Software\Classes\ms-settings\shell\open\command` or `HKCU\Software\Classes\CLSID\{F74662A2-2037-4F49-9F00-9312367F9B33}\shell\open\command`.
4. The attacker executes fodhelper.exe.
5. Due to the registry modifications, when fodhelper.exe runs, it executes the attacker's specified command with elevated privileges.
6. The attacker leverages the elevated privileges to install malware, create new user accounts with administrative rights, or modify system configurations.
7. The attacker might then perform lateral movement within the network, seeking to compromise additional systems.
8. The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or establishing persistent access.

## Impact

Successful exploitation of the Fodhelper UAC bypass can lead to complete system compromise. An attacker with elevated privileges can disable security controls, install malware, access sensitive data, and potentially pivot to other systems on the network. Organizations that do not monitor for this type of activity are at increased risk of data breaches, financial losses, and reputational damage. The use of this technique has been observed in conjunction with malware such as IcedID, ValleyRAT, and BlankGrabber Stealer.

## Recommendation

*   Enable Sysmon process creation logging to detect the execution of fodhelper.exe and its parent processes.
*   Monitor registry modifications to the `HKCU\Software\Classes\ms-settings\shell\open\command` or `HKCU\Software\Classes\CLSID\{F74662A2-2037-4F49-9F00-9312367F9B33}\shell\open\command` keys as mentioned in the attack chain.
*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious process creation events related to fodhelper.exe.
*   Investigate any instances of fodhelper.exe spawning child processes or accessing the registry keys mentioned above.
*   Implement application control policies to restrict the execution of unauthorized or potentially malicious programs.

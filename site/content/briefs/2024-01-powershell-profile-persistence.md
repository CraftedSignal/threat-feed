---
title: Persistence via PowerShell Profile Modification
slug: 2024-01-powershell-profile-persistence
description: Attackers can establish persistence by creating or modifying PowerShell profiles to execute malicious code each time PowerShell is launched, customizing the user environment.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - powershell
  - windows
vendors:
  - Microsoft
products:
  - PowerShell
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles
  - https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/
rules:
  - title: Detect PowerShell Profile Modification
    description: Detects the creation or modification of PowerShell profile scripts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.013
    data_sources:
      - file_event
      - windows
  - title: Detect PowerShell Profile in System32
    description: Detects the creation or modification of PowerShell profile scripts in System32, which is unusual.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.013
    data_sources:
      - file_event
      - windows
rules_count: 2
---

PowerShell profiles are scripts that execute when PowerShell starts, customizing the user environment. While often used legitimately, attackers can abuse this feature for persistence by injecting malicious code into these profiles. This technique allows the attacker to automatically execute code whenever a user opens a PowerShell session. This rule detects creation or modification events of PowerShell profile files, such as `profile.ps1` and `Microsoft.Powershell_profile.ps1`, within standard profile paths. Detecting these modifications can reveal potential malicious persistence mechanisms.

## Attack Chain

1. An attacker gains initial access to a system (e.g., through phishing or exploiting a vulnerability).
2. The attacker identifies the location of PowerShell profile scripts (e.g., `$PROFILE`, `$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1`).
3. The attacker modifies an existing PowerShell profile (e.g., `profile.ps1`) or creates a new one if it doesn't exist.
4. The attacker injects malicious PowerShell code into the profile, such as downloading and executing a payload, adding a backdoor, or establishing a reverse shell.
5. A user launches PowerShell, triggering the execution of the modified or created profile script.
6. The malicious code within the profile executes automatically, allowing the attacker to maintain persistence.
7. The attacker can perform actions such as gathering credentials, moving laterally within the network, or exfiltrating data.
8. The attacker maintains persistent access to the system as the malicious PowerShell code will execute every time a user launches PowerShell.

## Impact

Successful exploitation can lead to persistent access to compromised systems. Attackers can use this persistence to perform various malicious activities, including lateral movement, data exfiltration, and credential theft. The scope of impact depends on the privileges of the user whose profile is compromised.

## Recommendation

*   Deploy the Sigma rule "Detect PowerShell Profile Modification" to your SIEM to identify suspicious file modifications in PowerShell profile directories.
*   Enable Sysmon file event logging to ensure the "Detect PowerShell Profile Modification" rule functions correctly.
*   Monitor PowerShell execution logs for suspicious commands or scripts executed from PowerShell profiles.

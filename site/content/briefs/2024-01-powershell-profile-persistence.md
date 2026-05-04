---
title: Persistence via PowerShell Profile Modification
slug: 2024-01-powershell-profile-persistence
description: Attackers can modify PowerShell profiles to inject malicious code that executes each time PowerShell starts, establishing persistence on a Windows system.
date: "2024-01-02T18:17:05Z"
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
  - CrowdStrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Crowdstrike FDR
affected_os:
  - Windows
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
  - title: PowerShell Profile Modification
    description: Detects modification of PowerShell profile scripts, which can be used for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.013
    data_sources:
      - file_event
      - windows
  - title: Suspicious PowerShell Profile Location
    description: Detects PowerShell profiles created in system32 directory.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1546.013
    data_sources:
      - file_event
      - windows
rules_count: 2
---

PowerShell profiles are scripts that run when PowerShell starts, customizing the user's environment. Attackers can abuse this feature to gain persistence by modifying these profiles to execute malicious code each time a user launches PowerShell. The modification of PowerShell profiles allows the attacker to run arbitrary commands without requiring user interaction or explicit execution of malicious scripts. The targeted profile file names include `profile.ps1` and `Microsoft.Powershell_profile.ps1`, and the attack affects Windows systems where PowerShell is commonly used.

## Attack Chain

1.  The attacker gains initial access to the system through unspecified means.
2.  The attacker identifies the location of PowerShell profile scripts, typically found in `C:\Users\<Username>\Documents\WindowsPowerShell\`.
3.  The attacker modifies an existing PowerShell profile (e.g., `profile.ps1`) or creates a new one if it doesn't exist.
4.  The attacker injects malicious code into the PowerShell profile. This code could download and execute additional payloads, establish a reverse shell, or perform other malicious activities.
5.  The attacker ensures the malicious code runs when PowerShell is launched by modifying the profile content.
6.  When a user opens PowerShell, the profile script executes automatically, running the injected malicious code.
7.  The malicious code performs its intended actions, such as establishing persistence by creating scheduled tasks or modifying registry keys.

## Impact

Successful exploitation allows attackers to maintain persistent access to compromised systems. This persistence can be used to perform various malicious activities, including data theft, lateral movement, and deployment of ransomware. The severity is medium as it requires local access or prior compromise, but can lead to significant impact if successful.

## Recommendation

*   Deploy the Sigma rule "PowerShell Profile Modification" to detect unauthorized changes to PowerShell profile scripts.
*   Monitor file creation and modification events in the `C:\Users\*\Documents\WindowsPowerShell\` and `C:\Windows\System32\WindowsPowerShell\` directories for suspicious activity.
*   Enable PowerShell script block logging and transcription to gain visibility into the contents of PowerShell scripts being executed.
*   Restrict PowerShell usage to authorized personnel via Group Policy or other application control mechanisms.
*   Regularly audit PowerShell profiles for suspicious or unexpected code.

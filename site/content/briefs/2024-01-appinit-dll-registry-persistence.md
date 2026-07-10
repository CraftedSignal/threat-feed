---
title: AppInit DLL Registry Persistence Detected
slug: 2024-01-appinit-dll-registry-persistence
description: Modification of the AppInit DLLs registry keys can be used for persistence and defense evasion on Windows systems.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/010/
  - https://attack.mitre.org/techniques/T1112/
rules:
  - title: Detect AppInit DLL Registry Modification
    description: Detects modification of the AppInit_DLLs registry value, which can be used for persistence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
      - T1546.010
    data_sources:
      - registry_set
      - windows
  - title: Detect AppInit DLL Registry Creation
    description: Detects creation of the AppInit_DLLs registry value, which can be used for persistence.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
      - T1546.010
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The AppInit DLLs mechanism is a Windows feature where specified DLLs are loaded into every process that creates a user interface (loads user32.dll). This functionality is intended for customization of the user interface and behavior of Windows-based applications. However, adversaries can abuse this mechanism by adding malicious DLLs to the registry locations associated with AppInit DLLs. This allows them to execute arbitrary code with elevated privileges, similar to process injection, and establish a persistent presence on the compromised system. The rule monitors registry changes related to the `AppInit_DLLs` value.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through exploiting a vulnerability or social engineering).
2.  The attacker obtains administrative privileges on the system.
3.  The attacker modifies the Windows Registry to add a malicious DLL to the `AppInit_DLLs` value under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` or `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`.
4.  A new process is started that loads user32.dll, triggering the AppInit DLL mechanism.
5.  The malicious DLL is loaded into the newly created process's memory space.
6.  The malicious DLL executes its payload within the context of the process, allowing the attacker to perform malicious activities, such as lateral movement, data exfiltration, or establishing further persistence.

## Impact

Successful exploitation through AppInit DLL modification can lead to persistent code execution with elevated privileges. This allows attackers to maintain a foothold on the system, evade defenses, and potentially compromise sensitive data. The impact can range from data theft to complete system compromise, depending on the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule `Detect AppInit DLL Registry Modification` to your SIEM and tune for your environment to detect suspicious modifications to the AppInit DLLs registry keys.
*   Enable Windows Registry auditing and monitor for changes to the `AppInit_DLLs` registry keys to capture the events necessary for the Sigma rule.
*   Regularly review and validate the DLLs listed in the `AppInit_DLLs` registry keys to identify any unauthorized or suspicious entries.

---
title: Registry Persistence via AppInit DLL Modification
slug: 2024-01-appinit-dll-persistence
description: Modification of the AppInit DLLs registry keys on Windows systems allows attackers to execute code in every process that loads user32.dll, establishing persistence and potentially escalating privileges.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - appinit-dlls
  - registry
  - windows
vendors:
  - Microsoft
  - Commvault
  - Nvidia
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Windows
  - Microsoft Defender XDR
  - Commvault
  - Nvidia Display Driver
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - CrowdStrike FDR
affected_os:
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
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_appinitdlls_registry.toml
rules:
  - title: Registry Persistence via AppInit DLL Modification
    description: Detects modification of the AppInit_DLLs registry value to potentially load malicious DLLs into every process that loads user32.dll.
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
  - title: AppInit DLL Load from Unusual Location
    description: Detects DLLs loaded via AppInit_DLLs from locations outside standard program directories.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1546.010
    data_sources:
      - image_load
      - windows
rules_count: 2
---

The AppInit DLLs mechanism allows dynamic-link libraries (DLLs) to be loaded into every process that creates a user interface (loads user32.dll) on Microsoft Windows operating systems. This mechanism is intended for customization of the user interface and behavior of Windows-based applications. However, attackers can abuse this by adding malicious DLLs to the registry locations associated with AppInit DLLs. This enables them to execute code with elevated privileges, similar to process injection, and maintain a persistent presence on the compromised machine. This technique is often used to maintain access after initial compromise. Detection focuses on registry modifications to the relevant keys, excluding known legitimate processes to minimize false positives. The referenced Elastic rule was last updated on 2026/05/04.

## Attack Chain

1. An attacker gains initial access to the system through a vulnerability, phishing, or other means.
2. The attacker identifies the AppInit DLLs registry keys: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` or `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`.
3. The attacker modifies the `AppInit_DLLs` registry value to include the path to their malicious DLL.
4. The attacker's DLL is placed on the filesystem, typically in a location where it will persist across reboots.
5. Any new process that loads user32.dll will automatically load the attacker's malicious DLL.
6. The malicious DLL executes arbitrary code within the context of the newly created process.
7. The attacker can use this code execution to perform further actions, such as installing backdoors or escalating privileges.
8. The attacker maintains persistent access to the system through the malicious DLL loaded into every user interface process.

## Impact

Successful exploitation allows attackers to execute arbitrary code within the context of any process that loads `user32.dll`. This provides a persistent mechanism for maintaining access to the compromised system. The attacker gains code execution with elevated privileges, similar to process injection. This can lead to data theft, system compromise, or further lateral movement within the network. While no specific victim counts are mentioned, the widespread use of Windows makes this a potentially high-impact vulnerability.

## Recommendation

*   Monitor registry modifications to the `AppInit_DLLs` value in `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` and `HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows` using the "Registry Persistence via AppInit DLL Modification" Sigma rule.
*   Enable Sysmon registry event logging to provide the data required for the Sigma rule to function correctly.
*   Deploy the "Registry Persistence via AppInit DLL Modification" Sigma rule to your SIEM and tune the filter to exclude known-good DLL paths in your environment.
*   Investigate any alerts triggered by the Sigma rule, focusing on the parent process and the DLL being loaded.

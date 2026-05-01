---
title: Potential Credential Access via MSBuild Loading Credential Management DLLs
slug: 2024-01-02-msbuild-credential-dumping
description: The detection rule identifies a potential credential access attempt via the trusted developer utility MSBuild by detecting instances where it loads DLLs associated with Windows credential management, specifically vaultcli.dll or SAMLib.DLL, which is often used for credential dumping.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Elastic
products:
  - MSBuild
  - Elastic Defend
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
rules:
  - title: MSBuild Loads Credential Management DLL
    description: Detects instances of MSBuild loading vaultcli.dll or SAMLib.dll, which is often associated with credential dumping.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003
    data_sources:
      - image_load
      - windows
  - title: MSBuild Process Creation
    description: Detects the execution of MSBuild, potentially used for malicious purposes such as loading malicious DLLs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies potential credential access attempts leveraging the Microsoft Build Engine (MSBuild). Attackers may abuse MSBuild, a legitimate developer tool, to load malicious DLLs related to Windows credential management, such as `vaultcli.dll` or `SAMLib.dll`. This technique enables credential dumping by a trusted Windows utility, making it harder to detect. The rule focuses on detecting the loading of these specific DLLs by MSBuild processes. The rule relies on data from Elastic Defend and Sysmon logs.

## Attack Chain

1.  Attacker gains initial access to the target system (e.g., via phishing or exploiting a vulnerability).
2.  Attacker places a malicious `.csproj` file or a DLL designed to load credential management DLLs on the system.
3.  The attacker executes `MSBuild.exe` to process the malicious project file.
4.  `MSBuild.exe` loads the attacker-controlled DLL.
5.  The attacker-controlled DLL loads either `vaultcli.dll` or `SAMLib.dll`.
6.  The loaded DLLs are used to dump credentials from the system.
7.  The attacker accesses the dumped credentials.
8.  The attacker uses the compromised credentials for lateral movement or data exfiltration.

## Impact

A successful attack can lead to the compromise of sensitive credentials stored on the affected system. This can allow attackers to move laterally within the network, access confidential data, and potentially compromise entire domains. The impact ranges from data breaches to complete system compromise, depending on the privileges of the compromised accounts.

## Recommendation

*   Deploy the Sigma rule `MSBuild Loads Credential Management DLL` to your SIEM, tuned for your specific environment, to detect instances of MSBuild loading `vaultcli.dll` or `SAMLib.dll`.
*   Enable Sysmon event ID 7 (Image Loaded) logging with the appropriate configurations to capture DLL loading events.
*   Investigate any instances of MSBuild loading `vaultcli.dll` or `SAMLib.dll` from unusual or unexpected locations using the guidance in the rule note.

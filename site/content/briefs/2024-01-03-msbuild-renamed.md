---
title: Microsoft Build Engine Executed After Renaming
slug: 2024-01-03-msbuild-renamed
description: Attackers may rename the Microsoft Build Engine (MSBuild) executable to evade detection and proxy execution of malicious code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - msbuild
  - masquerading
vendors:
  - Microsoft
products:
  - MSBuild
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
references:
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1036/003/
  - https://attack.mitre.org/techniques/T1127/
  - https://attack.mitre.org/techniques/T1127/001/
rules:
  - title: Microsoft Build Engine Using an Alternate Name
    description: Detects the execution of MSBuild.exe with a different process name, indicating potential masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.003
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: MSBuild Spawned from Suspicious Process
    description: Detects MSBuild.exe being spawned from a suspicious parent process (cmd.exe, powershell.exe, etc.).
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1127.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may rename legitimate utilities, such as MSBuild, to evade detection, application allowlists, and other security protections. MSBuild, the Microsoft Build Engine, is a platform for building applications. Attackers can abuse MSBuild to proxy the execution of malicious code. The detection rule identifies instances where MSBuild is started after being renamed, indicating a potential attempt to evade detection. The rule focuses on identifying processes where the original file name is MSBuild.exe, but the process name is different, suggesting a renaming attempt.

## Attack Chain

1. An attacker gains initial access to a Windows system.
2. The attacker renames the legitimate MSBuild.exe executable to a different name (e.g., evil.exe) to evade detection.
3. The attacker executes the renamed MSBuild executable (evil.exe) with a malicious project file (.csproj or similar).
4. MSBuild processes the project file, which contains commands or scripts to be executed.
5. The malicious commands within the project file are executed by MSBuild, potentially downloading or executing further payloads.
6. The attacker may use MSBuild to execute PowerShell commands or other scripting languages for lateral movement or further exploitation.
7. MSBuild can be used to modify files, registry entries, or other system settings.
8. The attacker achieves their final objective, such as data exfiltration or establishing persistence.

## Impact

Successful exploitation can lead to arbitrary code execution, allowing attackers to install malware, steal sensitive information, or compromise the entire system. The renaming of MSBuild can bypass standard application allowlisting and detection mechanisms.

## Recommendation

*   Enable Sysmon process creation logging to capture the `Image` and `OriginalFileName` fields.
*   Deploy the Sigma rule "Microsoft Build Engine Using an Alternate Name" to your SIEM and tune for your environment to detect renamed MSBuild executables based on process metadata and command-line arguments.
*   Monitor process execution events for processes with `OriginalFileName` of "MSBuild.exe" and a different `process.name`.
*   Implement application control policies to restrict the execution of renamed executables, specifically those with an `OriginalFileName` of "MSBuild.exe."

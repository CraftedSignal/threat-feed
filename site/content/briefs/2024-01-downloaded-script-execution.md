---
title: Execution of Downloaded Windows Script
slug: 2024-01-downloaded-script-execution
description: This rule identifies the creation and execution of a Windows script downloaded from the internet, which adversaries may leverage for initial access and execution by exploiting unusual parent-child process relationships and script attributes.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - windows
  - scripting
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_windows_script_from_internet.toml
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/005/
  - https://attack.mitre.org/techniques/T1059/007/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/tactics/TA0002/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/techniques/T1218/007/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Downloaded Script File Creation followed by Scripting Host Execution
    description: Detects the creation of a script file downloaded from the internet followed by execution of a scripting utility.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Execution of Downloaded Windows Script via Mshta
    description: Detects execution of downloaded script using mshta.exe
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies instances where a Windows script file is created after being downloaded from the internet and subsequently executed using a scripting utility. Adversaries commonly exploit Windows script files for initial access and execution within a compromised environment. This technique involves downloading malicious scripts via web browsers or file utilities, followed by execution through scripting engines like `wscript.exe`, `cscript.exe`, or `mshta.exe`. The rule focuses on identifying anomalous parent-child process relationships and suspicious attributes associated with these scripts, such as their origin URL, referrer URL, and file extension. The detection logic specifically monitors the creation of script files with extensions like `.js`, `.vbs`, `.ps1`, and others, originating from internet sources, and their subsequent execution by scripting interpreters. This behavior is often indicative of malicious activity, potentially leading to further compromise or lateral movement within the network.

## Attack Chain

1. User downloads a malicious script file (e.g., `.js`, `.vbs`, `.ps1`) from the internet using a web browser such as Chrome, Edge, or Firefox or file utilites like Winrar or 7zip.
2. The downloaded file is saved to disk with the `creation` event being logged.
3. A scripting host process (e.g., `wscript.exe`, `cscript.exe`, `mshta.exe`, `powershell.exe`, `cmd.exe`) is spawned.
4. The scripting host process executes the downloaded script file, utilizing command-line arguments to specify the script's execution. For example, `wscript.exe malicious.vbs`.
5. The script performs malicious actions, such as downloading additional payloads or modifying system configurations.
6. Depending on the script's purpose, it may establish persistence, for instance, by creating scheduled tasks or modifying registry keys.
7. The script may attempt lateral movement by accessing network shares or exploiting vulnerabilities on other systems.
8. The final objective depends on the attacker's goals, ranging from data exfiltration to deploying ransomware.

## Impact

Successful exploitation can lead to arbitrary code execution, allowing attackers to gain control over the compromised system. This can result in data theft, system damage, or further propagation of the attack within the network. The detection rule aims to identify and prevent such attacks early in the attack chain. While the scope of targeting remains broad, organizations that do not properly vet external scripts face a greater risk. If successful, an attacker could move laterally within the network, potentially impacting hundreds or thousands of systems.

## Recommendation

*   Deploy the Sigma rule "Downloaded Script File Creation followed by Scripting Host Execution" to your SIEM to detect this activity (see rule below).
*   Deploy the Sigma rule "Execution of Downloaded Windows Script via Mshta" to your SIEM to specifically detect execution via `mshta.exe`.
*   Monitor process creation events for scripting hosts (`wscript.exe`, `cscript.exe`, `mshta.exe`, `powershell.exe`, `cmd.exe`) with command-line arguments pointing to downloaded script files.
*   Implement application control policies to restrict the execution of unauthorized scripting hosts.
*   Enforce strict download policies to prevent users from downloading executable content from untrusted sources.
*   Review the investigation steps outlined in the original rule documentation to improve triage efficiency.

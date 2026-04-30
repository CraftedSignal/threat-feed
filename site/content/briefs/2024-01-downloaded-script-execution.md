---
title: Execution of a Downloaded Windows Script
slug: 2024-01-downloaded-script-execution
description: This rule detects the execution of a Windows script downloaded from the internet, a technique adversaries may leverage for initial access and execution by using browsers or file utilities to download scripts and subsequently execute them with scripting tools like wscript or mshta.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - windows
  - script
  - initial_access
affected_os:
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
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
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
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1218/
rules:
  - title: Detect Windows Script Execution from Downloaded File
    description: This rule detects the execution of a Windows script file (e.g., .js, .vbs, .ps1) by a scripting engine (e.g., wscript.exe, powershell.exe) where the script file was recently created by a web browser. This is a common technique used by attackers to execute malicious code on a compromised system.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
      - T1059.005
      - T1059.007
      - T1218.005
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: Detect Downloaded Script Creation with Origin URL
    description: Detects the creation of a script file (e.g., .js, .vbs, .ps1) by a web browser with a populated origin URL or referrer URL, indicating that the script was downloaded from the internet.
    platform: sigma
    severity: low
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
    data_sources:
      - file_event
      - windows
  - title: Detect Scripting Utilities with High Argument Count
    description: Detects scripting utilities (wscript.exe, cscript.exe, powershell.exe) being executed with a high number of command-line arguments, which can indicate obfuscation or malicious intent.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule identifies the execution of Windows scripts that have been downloaded from the internet. Attackers often use scripting languages like PowerShell, VBScript, and JavaScript for initial access and execution within a compromised environment. They may download these scripts through web browsers or file utilities and then execute them using scripting engines such as `wscript.exe`, `cscript.exe`, or `mshta.exe`. This activity often bypasses traditional security controls, making it crucial for defenders to monitor for such behavior. The rule focuses on detecting unusual parent-child process relationships, where a browser downloads a script file, and a scripting engine subsequently executes it. This behavior is detected by monitoring file creation events from browsers and the subsequent execution of those files by scripting utilities.

## Attack Chain

1. A user browses to a malicious website or opens a compromised document.
2. The web browser (e.g., `chrome.exe`, `msedge.exe`) downloads a script file (e.g., `.js`, `.vbs`, `.ps1`) from a remote server. The downloaded file often has a recognizable origin URL or referrer URL.
3. The downloaded script is saved to the user's Downloads folder or another temporary directory.
4. The user, either unknowingly or through social engineering, executes the downloaded script.
5. A scripting engine (e.g., `wscript.exe`, `cscript.exe`, `powershell.exe`) is launched to interpret and run the script. The process arguments contain the path to the downloaded script.
6. The script performs malicious actions, such as downloading additional payloads, modifying system settings, or establishing a reverse shell.
7. The script may attempt to elevate privileges or propagate to other systems on the network.
8. The attacker achieves their objective, such as data exfiltration, ransomware deployment, or establishing persistent access.

## Impact

A successful attack can lead to a wide range of consequences, including malware infection, data theft, and system compromise. By using scripting languages, attackers can bypass application whitelisting and other security controls, making it difficult to detect and prevent the attack. The compromised system can then be used as a foothold for further attacks within the organization. A successful execution of a malicious script can lead to complete system compromise, potentially impacting all business operations reliant on that system.

## Recommendation

*   Enable process monitoring with command-line arguments to capture the execution of scripting engines and their associated scripts.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious script execution.
*   Implement application whitelisting to restrict the execution of unauthorized scripts and scripting utilities.
*   Review and analyze the parent-child process relationships to identify unusual process execution patterns as described in the Attack Chain.
*   Monitor file creation events from web browsers for script files originating from external URLs.

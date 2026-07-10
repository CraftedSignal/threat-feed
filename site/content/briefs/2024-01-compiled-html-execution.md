---
title: Execution via Compiled HTML File
slug: 2024-01-compiled-html-execution
description: Adversaries may abuse compiled HTML files (.chm) to execute malicious code by proxying execution via hh.exe, often leading to command execution via scripting interpreters.
date: "2024-01-02T14:21:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - compiled-html
  - execution
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - HTML Help system
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
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
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_via_compiled_html_file.toml
rules:
  - title: Detect Compiled HTML File Spawning Scripting Interpreters
    description: Detects execution of scripting interpreters (cmd, PowerShell, mshta) spawned by the HTML Help executable (hh.exe).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
      - T1218.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Process Activity via Compiled HTML File
    description: Detects suspicious processes spawned by the HTML Help executable (hh.exe).
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1218.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft HTML Help system uses compiled HTML files (.chm) as part of its normal operation. Adversaries may conceal malicious code within CHM files and deliver them to victims for execution. CHM content is loaded by the HTML Help executable program (hh.exe). This technique allows attackers to proxy the execution of malicious payloads via a signed binary, hh.exe, potentially bypassing security controls and gaining initial access to environments via social engineering. The original Elastic detection rule was created in February 2020 and last updated April 7, 2026. This poses a threat because hh.exe is a legitimate Microsoft signed binary, making it more difficult to detect malicious activity without specific monitoring of its child processes.

## Attack Chain

1.  The attacker crafts a malicious CHM file containing embedded code, such as JavaScript or shellcode.
2.  The attacker delivers the malicious CHM file to the victim, often via phishing or social engineering.
3.  The victim opens the CHM file, which is then processed by `hh.exe`.
4.  The `hh.exe` process executes the embedded malicious code within the CHM file.
5.  The malicious code spawns a child process, such as `cmd.exe`, `powershell.exe`, or `mshta.exe`, to execute further commands.
6.  The spawned process executes commands to download and execute a secondary payload, such as malware.
7.  The malware establishes persistence on the system, allowing the attacker to maintain access.
8.  The attacker performs actions on the compromised system, such as data exfiltration or lateral movement.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the victim's machine, leading to potential data compromise, system infection, and further malicious activity. The use of a signed Microsoft binary (hh.exe) makes detection more difficult, potentially allowing the attacker to operate undetected for a longer period. The impact ranges from single-machine compromise to wider network breaches depending on the attacker's objectives and capabilities.

## Recommendation

*   Deploy the Sigma rule "Detect Compiled HTML File Spawning Scripting Interpreters" to your SIEM and tune for your environment to detect the execution of scripting interpreters by `hh.exe`.
*   Monitor process creation events for `hh.exe` spawning child processes such as `cmd.exe`, `powershell.exe`, and `mshta.exe` to identify potential exploitation attempts.
*   Enable Sysmon process-creation logging to activate the rules above and ensure comprehensive logging of process activity.
*   Implement application control policies to restrict the execution of `cmd.exe`, `powershell.exe`, and `mshta.exe` by `hh.exe` to prevent exploitation.

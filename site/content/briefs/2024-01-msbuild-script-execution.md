---
title: Suspicious MSBuild Execution from Scripting Processes
slug: 2024-01-msbuild-script-execution
description: Adversaries may use MSBuild, a legitimate Microsoft tool, to execute malicious code through script interpreters for defense evasion and execution on Windows systems.
date: "2024-01-03T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - msbuild
  - proxy-execution
vendors:
  - Microsoft
products:
  - MSBuild
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
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
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_execution_msbuild_started_by_script.toml
  - https://attack.mitre.org/techniques/T1127/
  - https://attack.mitre.org/techniques/T1127/001/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1059/005/
  - https://attack.mitre.org/techniques/T1059/007/
rules:
  - title: Microsoft Build Engine Started by a Script Process
    description: Detects MSBuild execution initiated by scripting processes, indicative of potential defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MSBuild Command Line Arguments
    description: Detects suspicious command line arguments used with MSBuild, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1127.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft Build Engine (MSBuild) is a software build platform typically used by developers. However, attackers can abuse MSBuild to execute malicious code by using it as a proxy execution method, allowing them to bypass traditional defenses. This technique involves invoking MSBuild from scripting environments like PowerShell or cmd.exe to run arbitrary code within the context of a trusted process. The activity detected by this rule focuses on instances where MSBuild is launched by a script interpreter, which is not typical for standard software development workflows. This behavior, observed since at least 2020, can be used for stealthy execution of payloads and defense evasion tactics, especially in environments that trust MSBuild as a legitimate system utility. Defenders should be aware of this technique as it allows attackers to blend in with normal system activity and bypass application control policies.

## Attack Chain

1.  The attacker gains initial access to the target system, potentially through phishing or exploiting a software vulnerability.
2.  A script (e.g., PowerShell, cmd.exe) is used to execute a malicious command or series of commands.
3.  The script invokes `msbuild.exe` with specific arguments to execute arbitrary code. This might involve inline tasks or references to external XML project files containing malicious instructions.
4.  MSBuild processes the provided XML file or inline task, interpreting and executing the malicious code.
5.  The executed code performs actions such as downloading additional payloads, modifying system configurations, or establishing persistence.
6.  MSBuild, acting as a proxy, executes the attacker's code within a trusted process, potentially evading detection by security software.
7.  The attacker leverages the compromised system to move laterally within the network, escalating privileges, and accessing sensitive data.
8.  The attacker's final objective is achieved, such as data exfiltration or deploying ransomware.

## Impact

Successful exploitation allows attackers to execute arbitrary code on Windows systems, potentially leading to data theft, system compromise, and further propagation within the network. This technique can bypass application control and other security measures, making it difficult to detect and prevent. The impact can range from minor data breaches to complete system takeover, depending on the attacker's objectives and the compromised system's role within the organization.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) to capture the process tree and command-line arguments, enabling detection of suspicious MSBuild executions.
*   Deploy the Sigma rule `Microsoft Build Engine Started by a Script Process` to your SIEM to identify instances of MSBuild being invoked by script interpreters. Tune the rule with appropriate whitelisting for known development activities to reduce false positives.
*   Monitor process execution events for `msbuild.exe` with parent processes such as `cmd.exe`, `powershell.exe`, `cscript.exe`, and `mshta.exe`.
*   Implement application control policies to restrict the execution of MSBuild to authorized users and directories.
*   Regularly review and update the list of excluded processes and directories in the Sigma rule to adapt to changing development practices.

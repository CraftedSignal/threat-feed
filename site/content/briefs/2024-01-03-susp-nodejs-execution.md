---
title: Suspicious Execution with NodeJS
slug: 2024-01-03-susp-nodejs-execution
description: This rule detects suspicious Node.js execution patterns on Windows systems, including user-writable runtimes, preload arguments, and inline eval, decode, or child-process usage, indicating potential malicious activity.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - nodejs
  - execution
  - windows
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
  - OpenJS Foundation
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Sysmon
  - Windows Security Event Logs
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
references:
  - https://nodejs.org/api/child_process.html
  - https://nodejs.org/api/globals.html#atobdata
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_nodejs_susp_patterns.toml
rules:
  - title: Node.js Executed from User AppData
    description: Detects Node.js being executed from user-writable AppData directories, which can indicate malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Node.js PowerShell Preload Argument
    description: Detects Node.js being executed with the -r argument by PowerShell, indicating a potential module preload attack.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Node.js Inline Code Execution
    description: Detects Node.js command lines containing eval, atob, or require*child_process*, indicating potential inline code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection identifies suspicious Node.js execution patterns on Windows systems. Attackers may leverage Node.js, especially if it's running from user-writable locations, to execute malicious code. The rule focuses on identifying instances where Node.js is executed from unusual paths like AppData, uses preload arguments (-r) potentially to inject malicious modules, or uses inline JavaScript execution techniques like `eval`, `atob`, or `child_process` to spawn other processes. The rule is designed to work with multiple data sources, including Elastic Defend, CrowdStrike, Microsoft Defender XDR, SentinelOne, Sysmon, and Windows Security Event Logs. This is important for defenders as malicious Node.js execution can lead to code injection, privilege escalation, and ultimately, system compromise.

## Attack Chain

1.  A user downloads or receives a malicious Node.js script, often disguised as a legitimate file.
2.  The script is saved to a user-writable directory such as the user's AppData folder.
3.  The attacker executes `node.exe` from the AppData directory, specifying the malicious script as an argument.
4.  Alternatively, PowerShell is used to launch Node.js with the `-r` argument to preload a malicious module, bypassing standard execution controls.
5.  The Node.js script uses the `eval()` or `atob()` functions to execute obfuscated code.
6.  The script leverages the `child_process` module to spawn a new process, such as `cmd.exe` or `powershell.exe`.
7.  The spawned process executes malicious commands, potentially downloading additional payloads or establishing a reverse shell.
8.  The attacker gains unauthorized access to the system and performs malicious activities, such as data exfiltration or lateral movement.

## Impact

A successful attack could lead to a complete compromise of the affected system. This includes the potential for data theft, installation of backdoors, and further propagation of the attack to other systems on the network. While the number of victims is not specified, the broad applicability of Node.js makes this a significant threat across various sectors.

## Recommendation

*   Deploy the "Suspicious Execution with NodeJS" Sigma rule to your SIEM to detect the execution patterns described in this brief, tuning it for your specific environment.
*   Monitor process creation events for `node.exe` executing from user-writable paths like `\Users\*\AppData\*`, as highlighted in the Sigma rule and attack chain.
*   Investigate any instances of `node.exe` being launched with the `-r` argument by `powershell.exe`, as this indicates a potential module preload attack, which is covered in the Sigma rule.
*   Review command-line arguments for `node.exe` containing `eval(`, `atob(`, or `require*child_process*` to identify potential inline code execution and child process spawning, as per the Sigma rule description.

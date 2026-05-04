---
title: Execution from Unusual Directory - Command Line
slug: 2024-01-03-execution-from-unusual-directory
description: This rule identifies process execution from suspicious default Windows directories, which adversaries may abuse to hide malware in trusted paths to evade defenses.
date: "2024-01-03T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - defense-evasion
  - windows
  - process-execution
vendors:
  - Microsoft
products:
  - Microsoft Defender XDR
  - Windows Security Event Logs
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
  - https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language
rules:
  - title: Execution from Unusual Directory - Command Line
    description: Detects process execution from suspicious default Windows directories.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Windows Script Host Execution from Temp Directories
    description: Detects wscript.exe or cscript.exe execution from the Temp directory.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies instances of process execution originating from suspicious default Windows directories. Attackers often exploit these locations to conceal malware, leveraging the implicit trust associated with system or application paths to evade security measures. This tactic is employed to make malicious executions appear less conspicuous. The rule focuses on detecting specific processes, including `wscript.exe`, `cscript.exe`, `rundll32.exe`, `regsvr32.exe`, and others, when they are executed from unusual directories, such as `C:\\PerfLogs\\`, `C:\\Users\\Public\\`, and `C:\\Windows\\Tasks\\`. The intent is to highlight anomalous process behaviors that deviate from expected norms, providing early warning of potential malicious activity. The detection logic also includes filters to reduce false positives by excluding known legitimate executables and command line arguments from the specified directories.

## Attack Chain

1. An attacker gains initial access to a Windows system through various means such as phishing or exploiting a vulnerability.
2. The attacker uploads or drops a malicious payload into a suspicious directory like `C:\\Users\\Public\\` or `C:\\Windows\\Tasks\\`.
3. The attacker uses a legitimate Windows utility such as `cmd.exe`, `powershell.exe`, or `wscript.exe` to execute the malicious payload.
4. The executed script or binary performs malicious actions, such as establishing persistence.
5. The attacker attempts to evade detection by masquerading the malicious activity as legitimate system processes.
6. The malware may attempt to communicate with a command-and-control server.
7. The malware may perform lateral movement within the network.
8. The final objective of the attacker is to exfiltrate sensitive data or cause damage to the system.

## Impact

Successful exploitation can lead to malware infection, data compromise, and system instability. Attackers can establish persistent access, escalate privileges, and perform lateral movement within the network. The impact ranges from minor disruptions to significant data breaches depending on the attacker's objectives and the compromised system's role within the organization. The targeted sectors are broad, as this technique is applicable across various industries and organizational sizes.

## Recommendation

*   Deploy the Sigma rule "Execution from Unusual Directory - Command Line" to your SIEM and tune for your environment to detect suspicious process executions from unusual directories.
*   Investigate any alerts triggered by the Sigma rule, focusing on the process execution chain and command-line arguments.
*   Enable process creation logging with command line arguments to provide the necessary data for the Sigma rule (reference log source in rule).
*   Regularly review and update the list of suspicious directories in the Sigma rule to reflect changes in your environment.
*   Implement application whitelisting to restrict the execution of unauthorized applications from unusual directories.

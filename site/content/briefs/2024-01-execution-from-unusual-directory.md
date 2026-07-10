---
title: Execution from Unusual Directory - Command Line
slug: 2024-01-execution-from-unusual-directory
description: Adversaries may execute commands and scripts from unusual Windows directories to masquerade malware and evade detection, impacting system integrity and security operations.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - defense-evasion
  - windows
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
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
  - https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language
rules:
  - title: Execution from Unusual Directory - Command Line
    description: Detects execution of processes from unusual directories via command line.
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
  - title: Suspicious Rundll32 Execution from Unusual Path
    description: Detects rundll32.exe executing a DLL from an unusual directory.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies instances where common Windows executables such as `powershell.exe`, `cmd.exe`, `wscript.exe`, and `rundll32.exe` are launched with command-line arguments that specify paths within suspicious or unusual directories. Attackers may leverage these locations to conceal malicious scripts or binaries, making them appear legitimate and bypass standard security measures. These locations include `C:\\PerfLogs\\`, `C:\\Users\\Public\\`, and numerous other default Windows directories where execution is not typically expected. This activity can be part of a broader masquerading or defense evasion strategy, allowing malware to operate undetected for extended periods. This detection uses EQL to analyze process execution events and identify deviations from normal behavior based on command-line arguments.

## Attack Chain

1.  An attacker gains initial access to a Windows system (e.g., via phishing or exploit).
2.  The attacker uploads a malicious script (e.g., PowerShell script) to a suspicious directory like `C:\\Users\\Public\\`.
3.  The attacker uses `cmd.exe` or `powershell.exe` to execute the script, masking its true purpose.
4.  `cmd.exe` or `powershell.exe` executes from a location such as `C:\\Windows\\System32\\`, while the script runs from `C:\\Users\\Public\\`.
5.  The malicious script performs actions like downloading additional payloads or modifying registry keys for persistence.
6.  The attacker leverages `rundll32.exe` to execute a DLL from a non-standard directory like `C:\\Windows\\Tasks\\` to evade detection.
7.  The executed code establishes a reverse shell connection to an external C2 server.
8.  The attacker achieves persistence and control over the compromised system, potentially leading to data theft or further malicious activities.

## Impact

Successful exploitation can lead to malware residing undetected on the system, allowing attackers to perform actions such as data exfiltration, lateral movement, or system compromise. Due to the nature of defense evasion, affected systems may remain compromised for extended periods, amplifying the potential damage. While the scale of impact varies, organizations across different sectors that rely on Windows-based systems are vulnerable. The severity can range from minor data breaches to complete system takeovers, depending on the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule "Execution from Unusual Directory" to your SIEM to identify suspicious process executions. Tune the rule by excluding legitimate software that may trigger false positives in your environment.
*   Monitor process creation events, specifically focusing on the command-line arguments and parent-child process relationships to identify potentially malicious behavior (Data Source: Sysmon, Windows Security Event Logs).
*   Use threat intelligence platforms to investigate SHA-256 hash values of executables identified by the Sigma rule, checking for known malicious signatures (references: VirusTotal, Hybrid-Analysis).

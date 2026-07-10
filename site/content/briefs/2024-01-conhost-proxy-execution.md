---
title: Conhost Proxy Execution for Defense Evasion
slug: 2024-01-conhost-proxy-execution
description: Adversaries abuse the Console Window Host (conhost.exe) with the `--headless` argument to proxy command execution, evading detection by blending malicious activity with legitimate Windows software.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - proxy-execution
  - conhost
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
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
  - https://lolbas-project.github.io/lolbas/Binaries/Conhost/
  - https://attack.mitre.org/techniques/T1202/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
rules:
  - title: Conhost Headless Execution with Suspicious CommandLine
    description: Detects conhost.exe executions with --headless argument and suspicious command lines indicative of proxy execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Conhost Proxy Execution with Suspicious CommandLine
    description: Detects conhost.exe executions with a suspicious command line and is a child process of a potential exploit.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Console Window Host (conhost.exe) is a legitimate Windows process used to provide a command-line interface. Adversaries are known to abuse conhost.exe, specifically with the `--headless` argument, to proxy the execution of malicious commands. This technique is employed as a defense evasion tactic to blend malicious activity with legitimate Windows software, making it harder for security tools to detect. The observed behavior involves spawning conhost.exe processes with command-line arguments indicative of command execution via PowerShell, cmd, or other scripting interpreters. This activity has been observed across various environments, highlighting the need for proactive detection measures.

## Attack Chain

1. An adversary gains initial access to a Windows system (e.g., via phishing or exploiting a vulnerability).
2. The adversary executes a malicious script or binary on the compromised system.
3. The script or binary spawns conhost.exe with the `--headless` argument to create a hidden console window.
4. The adversary uses conhost.exe to execute commands via proxy, such as PowerShell or cmd.exe, within the hidden console window. This allows for commands to be executed without a visible console window.
5. The executed commands download and execute further payloads, such as malware or tools for lateral movement.
6. The adversary uses these tools to perform reconnaissance, escalate privileges, and move laterally within the network.
7. The adversary compromises additional systems and gains access to sensitive data.
8. The final objective is achieved (e.g., data exfiltration, ransomware deployment).

## Impact

Successful exploitation allows attackers to execute arbitrary commands on the target system while potentially evading detection. This can lead to data theft, system compromise, and further propagation within the network. The use of `conhost.exe` for proxy execution can obscure malicious activity, making it more difficult for security tools to identify and block the attack.

## Recommendation

*   Monitor process creation events for `conhost.exe` with the `--headless` argument. Deploy the Sigma rule "Conhost Headless Execution with Suspicious CommandLine" to detect this specific behavior.
*   Inspect the command-line arguments of `conhost.exe` processes for suspicious strings indicative of command execution via PowerShell, cmd, or other scripting interpreters, as detailed in the rule description.
*   Enable Sysmon process creation logging to capture detailed information about process execution, including command-line arguments and parent processes, which will enable the Sigma rule "Conhost Proxy Execution with Suspicious CommandLine".
*   Correlate conhost.exe process execution events with other suspicious activity on the system, such as network connections to unusual destinations or file modifications in sensitive areas.
*   Regularly review and update detection rules to account for new and evolving attacker techniques.

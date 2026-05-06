---
title: Suspicious Command Execution via WMI
slug: 2024-01-suspicious-wmi-cmd
description: Detects suspicious command execution via WMI on a Windows host, potentially indicating lateral movement by an adversary using cmd.exe to execute commands remotely.
date: "2024-01-03T15:22:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral movement
  - wmi
  - cmd.exe
  - execution
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Elastic Defend
  - Elastic Endgame
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
  - https://www.elastic.co/security-labs/operation-bleeding-bear
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_suspicious_cmd_wmi.toml
rules:
  - title: Suspicious Cmd Execution via WMI
    description: Detects suspicious command execution (cmd) via Windows Management Instrumentation (WMI) on a remote host.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
  - title: Cmd Execution with Loopback Admin Share
    description: Detects cmd.exe executing with arguments indicative of writing to a loopback admin share, a common technique for capturing command output via WMI.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies suspicious command execution via Windows Management Instrumentation (WMI) on a remote Windows host. The rule focuses on detecting instances where `cmd.exe` is executed by `WmiPrvSE.exe` (the WMI Provider Host process) with specific command-line arguments indicative of remote execution and output capture. These arguments include `/c`, `/Q`, `2>&1`, and `1>`, often used for quiet execution and redirection of standard output and standard error. The command-line arguments also include common temp paths and loopback addresses, suggesting attempts to capture output for later retrieval. This activity is often associated with lateral movement techniques employed by attackers and can be an early indicator of compromise. The rule is designed to work with data from various sources, including Elastic Defend, Microsoft Defender XDR, SentinelOne, Crowdstrike, and Sysmon.

## Attack Chain

1.  **Initial Access:** An attacker compromises a user account or leverages an existing vulnerability to gain initial access to a system on the network.
2.  **Credential Access:** The attacker attempts to harvest credentials from the compromised system using various techniques, such as dumping credentials from memory.
3.  **Lateral Movement:** The attacker uses the compromised credentials to move laterally to other systems on the network.
4.  **WMI Execution:** The attacker leverages WMI to execute commands on a remote host. This involves using the `WmiPrvSE.exe` process to launch `cmd.exe`.
5.  **Command Execution:** The attacker executes a command using `cmd.exe` with arguments like `/c`, `/Q`, `2>&1`, and `1>`, designed for quiet execution and redirection of output.
6.  **Output Redirection:** The output of the command is redirected to a temporary file location, often within the `C:\windows\temp\` directory, or to a network share on the local system (e.g., `\\\\127.0.0.1\\C$\\Windows\\Temp\\*`). The attacker might also encode the output.
7.  **Data Collection:** The attacker retrieves the output from the temporary file or network share, collecting information or further compromising the system.
8.  **Privilege Escalation/Persistence:** The attacker uses the collected information to escalate privileges or establish persistence on the compromised system.

## Impact

Successful exploitation can lead to widespread compromise of systems within the network. Attackers can use WMI to remotely execute malicious commands, steal sensitive data, install malware, or further propagate their attack. The impact can range from data theft and system disruption to complete network compromise. The use of WMI allows attackers to operate stealthily and evade traditional security measures, making detection and response challenging.

## Recommendation

*   Deploy the provided Sigma rule `Suspicious Cmd Execution via WMI` to your SIEM to detect suspicious command execution via WMI, and tune it for your environment.
*   Enable Sysmon process creation logging (Event ID 1) to ensure the necessary data is available for the Sigma rule to function effectively, as indicated in the [setup documentation](https://ela.st/sysmon-event-1-setup).
*   Review and restrict remote WMI access to only authorized administrative accounts and systems to limit the attack surface, as mentioned in the triage and analysis steps.
*   Investigate any alerts generated by this rule to determine the scope and impact of the potential compromise, focusing on the command intent, session details, and child processes created, as described in the triage section.

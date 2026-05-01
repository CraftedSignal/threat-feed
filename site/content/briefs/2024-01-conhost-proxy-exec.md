---
title: Conhost Proxy Execution for Defense Evasion
slug: 2024-01-conhost-proxy-exec
description: Adversaries abuse the Console Window Host (conhost.exe) with the `--headless` argument to proxy execution of malicious commands, evading detection by blending in with legitimate Windows software.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - proxy-execution
  - windows
vendors:
  - Elastic
  - Crowdstrike
  - Microsoft
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Conhost/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_indirect_exec_conhost.toml
rules:
  - title: Conhost Headless Execution with Suspicious Arguments
    description: Detects conhost.exe executing with the --headless argument and suspicious command-line arguments indicative of malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.013
    data_sources:
      - process_creation
      - windows
  - title: Conhost with Headless and Caret-Escaped Characters
    description: Detects conhost.exe executing with the --headless argument and caret-escaped characters in the command line, often used to bypass security restrictions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.013
    data_sources:
      - process_creation
      - windows
  - title: Conhost Proxying Remote File Retrieval
    description: Detects conhost.exe with --headless proxying commands commonly used for remote file retrieval.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1105
      - T1218.013
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers are leveraging the Console Window Host (conhost.exe) to proxy execution of commands, using the `--headless` argument to hide malicious activity. This technique allows adversaries to blend in with legitimate Windows processes, making detection more challenging. This behavior, often associated with defense evasion, involves using conhost.exe to execute commands such as PowerShell, cmd.exe, mshta, curl, and scripts. The activity can be seen across multiple environments including endpoints, Windows systems, and cloud platforms like Microsoft Defender XDR and SentinelOne. Defenders must differentiate between legitimate uses of conhost.exe, such as those by Winget-AutoUpdate or OpenSSH, and malicious proxy executions, which could indicate broader compromise.

## Attack Chain

1.  An attacker gains initial access to the system, possibly through phishing or exploiting a vulnerability.
2.  The attacker executes a command that calls conhost.exe with the `--headless` argument.
3.  Conhost.exe is used to proxy the execution of a malicious command, such as PowerShell, cmd.exe, or mshta.
4.  The proxied command downloads a malicious payload from a remote server using tools like curl or bitsadmin.
5.  The downloaded payload is executed, establishing persistence on the compromised system.
6.  The attacker uses the compromised system to move laterally within the network, compromising additional systems.
7.  Sensitive data is exfiltrated from the network to a remote server controlled by the attacker.
8.  The attacker achieves their final objective, such as deploying ransomware or stealing intellectual property.

## Impact

Successful exploitation can lead to a complete compromise of the targeted system and potentially the entire network. This can result in data theft, financial loss, and reputational damage. The use of `conhost.exe` for proxy execution makes it difficult to detect malicious activity, potentially allowing attackers to remain undetected for extended periods. The impact could range from individual workstation compromises to large-scale network breaches, affecting potentially hundreds or thousands of systems within an organization.

## Recommendation

*   Deploy the "Proxy Execution via Console Window Host" Sigma rule to your SIEM and tune for your environment to detect suspicious `conhost.exe` activity.
*   Monitor process creation events for `conhost.exe` with the `--headless` argument, focusing on the command-line arguments to identify potentially malicious commands.
*   Investigate any instances of `conhost.exe` executing suspicious scripts, downloaders, or task scheduler modifications to identify potential threats.
*   Enable Sysmon process creation logging (Event ID 1) to capture detailed process execution information, as recommended in the setup instructions linked in the overview.
*   Review the investigation fields in the brief to understand the key data points for analyzing potential proxy execution attempts.

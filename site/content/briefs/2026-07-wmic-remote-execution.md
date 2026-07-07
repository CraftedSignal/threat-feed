---
title: WMIC Remote Command Execution Detection
slug: 2026-07-wmic-remote-execution
description: This brief focuses on detecting the abuse of the Windows Management Instrumentation Command-line (WMIC) utility to execute commands or query information on remote systems, a common technique used by attackers for lateral movement and reconnaissance within compromised networks.
date: "2026-07-03T14:55:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - reconnaissance
  - execution
  - wmic
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: Detects the execution of WMIC to query information on a remote system.
    confidence_band: high
references:
  - https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_remote_execution.yml
rules:
  - title: WMIC Remote Command Execution
    description: Detects the execution of WMIC to query information or execute commands on a remote system via the '/node:' parameter, excluding localhost targets.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This threat brief details the detection of the Windows Management Instrumentation Command-line (WMIC) utility being used to interact with remote systems. WMIC is a legitimate built-in Windows command-line utility that allows administrators to manage local and remote Windows machines using Windows Management Instrumentation (WMI). Threat actors frequently abuse WMIC to perform various malicious activities, including executing arbitrary commands, querying system information, listing processes, or creating/modifying services on remote hosts. The presence of WMIC with the `/node:` parameter indicates an attempt to target a different machine, which, if not part of legitimate administrative activity, can signify lateral movement, reconnaissance, or remote execution by an adversary. While the provided Sigma rule focuses on the technical detection aspect, this activity is a cornerstone for many sophisticated attacks to expand their footprint within an environment.

## Attack Chain

1.  **Initial Compromise**: An attacker gains initial access to a workstation or server (e.g., via phishing, exposed vulnerability, or credential stuffing).
2.  **Internal Reconnaissance**: The attacker uses tools or native commands (e.g., `net group "Domain Admins" /domain`) to identify other systems or user accounts.
3.  **Credential Acquisition**: Credentials, often through tools like Mimikatz or by exploiting vulnerable services, are obtained for elevated access or other user accounts.
4.  **Lateral Movement via WMIC**: The attacker utilizes `wmic.exe` with the `/node:` parameter and valid credentials to connect to a target remote system.
5.  **Remote Execution/Query**: On the remote system, the attacker executes commands (e.g., `process call create "cmd /c dir C:\\"`) or queries sensitive information (e.g., `ComputerSystem Get UserName`) via WMIC.
6.  **Persistence/Further Actions**: If successful, the attacker may establish persistence on the new host, install additional malware, or continue lateral movement to other systems, ultimately aiming for data exfiltration or disruptive impact.

## Impact

While the detection of WMIC remote execution itself is an indicator of compromise rather than the final impact, its successful exploitation can lead to significant consequences. Attackers leveraging this technique can achieve arbitrary code execution on remote systems, facilitating lateral movement across the network without relying on more easily detectable tools. This enables them to gain access to sensitive data, escalate privileges, deploy ransomware, or establish long-term persistence within an organization's infrastructure. If not detected and mitigated, this activity can be a crucial step towards a full network compromise, leading to data breaches, operational disruption, and severe financial and reputational damage.

## Recommendation

*   Deploy the `WMIC Remote Command Execution` Sigma rule in this brief to your SIEM and tune for your environment to detect suspicious remote WMIC activity.
*   Enable Sysmon process-creation logging (Event ID 1) to ensure the necessary telemetry for the `WMIC Remote Command Execution` rule.
*   Implement strong credential hygiene and multi-factor authentication to prevent attackers from acquiring credentials necessary for remote WMIC execution.
*   Restrict administrative access to systems and implement least privilege principles to limit the potential impact of a compromised account capable of using WMIC remotely.
*   Monitor authentication logs for suspicious logon attempts against service accounts or critical systems that could precede WMIC-based lateral movement.

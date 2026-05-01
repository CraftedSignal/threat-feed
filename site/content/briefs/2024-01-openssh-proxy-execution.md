---
title: Proxy Execution via Windows OpenSSH Client
slug: 2024-01-openssh-proxy-execution
description: Detection of command execution via proxy using the Windows OpenSSH client (ssh.exe or sftp.exe) to bypass application control using trusted Windows binaries.
date: "2024-01-03T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - proxy-execution
  - openssh
  - application-control-bypass
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - M365 Defender
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ssh/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_indirect_exec_openssh.toml
rules:
  - title: Proxy Execution via Windows OpenSSH
    description: Detects attempts to execute commands via proxy using the Windows OpenSSH client, potentially indicating an attempt to bypass application control.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: OpenSSH ProxyCommand with LOLBIN
    description: Detects OpenSSH usage with ProxyCommand executing Living Off The Land Binaries
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies attempts to execute commands through a proxy using the Windows OpenSSH client (ssh.exe or sftp.exe). Attackers may abuse this behavior to evade application control policies by leveraging the trusted Windows OpenSSH binaries. The technique involves using the `ProxyCommand` or `LocalCommand` options with the OpenSSH client to execute arbitrary commands on the target system. The rule focuses on detecting command lines containing potentially malicious commands such as PowerShell, schtasks, mshta, msiexec, cmd, or script execution, indicating a possible attempt to bypass security measures. The detection logic is applicable to Windows systems.

## Attack Chain

1.  An attacker gains initial access to a Windows system.
2.  The attacker executes the Windows OpenSSH client (ssh.exe or sftp.exe) with either the `ProxyCommand` or `LocalCommand` option.
3.  The `ProxyCommand` or `LocalCommand` parameter specifies a command to be executed locally on the system.
4.  The command includes potentially malicious payloads such as PowerShell commands, scheduled tasks manipulation (schtasks), or execution of other LOLBINs (Living Off the Land Binaries) like mshta or msiexec.
5.  The OpenSSH client executes the specified command.
6.  The malicious command performs actions such as downloading and executing additional payloads, creating scheduled tasks for persistence, or executing arbitrary code.
7.  The attacker achieves their objectives, such as gaining further access to the system, escalating privileges, or deploying malware.

## Impact

Successful exploitation can lead to a complete compromise of the affected system. Attackers can bypass application control mechanisms, execute arbitrary code, and establish persistence. This can result in data theft, system disruption, or further propagation of the attack within the network. The severity of the impact depends on the privileges of the account running the OpenSSH client and the specific actions performed by the malicious commands.

## Recommendation

*   Enable process creation logging with command line details to capture the execution of ssh.exe and sftp.exe with malicious parameters.
*   Deploy the Sigma rule `Proxy Execution via Windows OpenSSH` to your SIEM to detect suspicious OpenSSH client executions with malicious commands in the command line.
*   Monitor for the creation of child processes from ssh.exe or sftp.exe, as this can indicate the execution of malicious commands specified in the `ProxyCommand` or `LocalCommand` options.
*   Review and restrict the usage of `PermitLocalCommand` in OpenSSH server configurations to prevent attackers from executing commands locally on the system after a connection is established.

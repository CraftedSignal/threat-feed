---
title: Incoming Execution via PowerShell Remoting
slug: 2024-01-03-powershell-remoting
description: This rule identifies remote execution via Windows PowerShell remoting, which allows a user to run any Windows PowerShell command on one or more remote computers, potentially indicating lateral movement.
date: "2024-01-03T18:53:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - powershell
  - remoting
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - PowerShell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1
rules:
  - title: Incoming Execution via PowerShell Remoting - Network Connection
    description: Detects incoming network connections associated with PowerShell Remoting on ports 5985 and 5986.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.006
    data_sources:
      - network_connection
      - windows
  - title: Incoming Execution via PowerShell Remoting - Process Creation
    description: Detects processes spawned by wsmprovhost.exe, indicating remote PowerShell execution.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies potential lateral movement through the exploitation of Windows PowerShell remoting. PowerShell remoting is a feature that enables administrators and attackers to execute commands on remote Windows systems. The detection focuses on identifying incoming network connections on ports 5985 (HTTP) and 5986 (HTTPS), the default ports used for PowerShell Remoting, followed by the execution of processes spawned by `wsmprovhost.exe`, the Windows Remote Management process host. This activity, when originating from unexpected sources, may indicate unauthorized access and lateral movement within a network. The rule is designed to detect suspicious activity by monitoring network traffic and process execution, flagging potential unauthorized remote executions, and enabling security teams to respond swiftly.

## Attack Chain

1. An attacker gains initial access to a network, possibly through phishing or exploiting a vulnerability on an internet-facing system.
2. The attacker leverages PowerShell remoting to initiate a connection to a target system on ports 5985 or 5986.
3. The target system accepts the incoming PowerShell Remoting connection.
4. The `wsmprovhost.exe` process is launched on the target system to facilitate the remote PowerShell session.
5. The attacker executes commands remotely, spawning child processes from `wsmprovhost.exe`.
6. The attacker attempts to escalate privileges or move laterally to other systems within the network using the remote PowerShell session.
7. The attacker uses tools such as `net.exe` or `PsExec` over the remote PowerShell session to further propagate.
8. The attacker achieves their objective, such as data exfiltration or deploying ransomware, by leveraging the established remote session.

## Impact

Successful exploitation of PowerShell Remoting for lateral movement can lead to widespread compromise within an organization. An attacker could gain control over multiple systems, potentially leading to data breaches, system outages, or ransomware deployment. The number of affected systems could range from a few critical servers to a significant portion of the network, depending on the attacker's objectives and the organization's security posture. The impact could include financial losses, reputational damage, and disruption of business operations.

## Recommendation

*   Deploy the Sigma rule `Incoming Execution via PowerShell Remoting` to your SIEM to detect suspicious PowerShell remoting activity and tune for your environment.
*   Monitor network connections to ports 5985 and 5986, and investigate any unauthorized or unexpected traffic using the `network_connection` log source.
*   Investigate processes spawned by `wsmprovhost.exe` for unusual or malicious activity using the `process_creation` log source.
*   Whitelist authorized administrative IP addresses or user accounts that frequently perform remote management tasks, as mentioned in the false positives analysis.
*   Review and document automated scripts or scheduled tasks that use PowerShell Remoting for system maintenance, then create exceptions for their specific process names or execution paths.

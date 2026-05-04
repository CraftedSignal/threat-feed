---
title: Suspicious ScreenConnect Client Child Process Activity
slug: 2024-05-screenconnect-child-process
description: This rule identifies suspicious child processes spawned by ScreenConnect client processes, potentially indicating unauthorized access and command execution abusing ScreenConnect remote access software to perform malicious activities such as data exfiltration or establishing persistence.
date: "2024-05-16T16:10:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - defense-evasion
  - execution
  - persistence
  - screenconnect
vendors:
  - Elastic
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - ScreenConnect
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Tools
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
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
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
cves:
  - id: CVE-2024-1709
    cvss: 10
    epss: 0.94322
  - id: CVE-2024-1708
    cvss: 8.4
    epss: 0.84882
references:
  - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
rules:
  - title: ScreenConnect Spawning Suspicious Processes
    description: Detects suspicious processes spawned by ScreenConnect client processes, indicating potential unauthorized command execution.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1053.005
      - T1059.001
      - T1059.003
      - T1218
      - T1218.005
      - T1218.011
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: ScreenConnect Spawning Net.exe Adding User
    description: Detects net.exe being spawned by ScreenConnect client processes with arguments indicating user creation, a sign of potential privilege escalation or unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - privilege_escalation
    techniques:
      - T1059.003
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the detection of suspicious activities related to the ScreenConnect remote access tool. ScreenConnect is a legitimate remote support software, but adversaries can exploit it to execute unauthorized commands on compromised systems. This detection identifies suspicious child processes spawned by ScreenConnect client processes, such as `ScreenConnect.ClientService.exe` or `ScreenConnect.WindowsClient.exe`, which can indicate malicious activities such as spawning PowerShell or cmd.exe with unusual arguments. This activity can indicate potential abuse of remote access capabilities, leading to data exfiltration, command and control communication, or the establishment of persistence mechanisms. Recent exploitation of CVE-2024-1709 and CVE-2024-1708 have highlighted the risk associated with ScreenConnect exploitation.

## Attack Chain

1.  The attacker gains unauthorized access to a system with ScreenConnect installed. This could be achieved through exploiting vulnerabilities like CVE-2024-1709 and CVE-2024-1708, or through credential compromise.
2.  The attacker uses ScreenConnect to connect to the compromised system remotely.
3.  The attacker uses the ScreenConnect interface to execute commands on the remote system.
4.  The attacker spawns a command interpreter, such as `cmd.exe`, using ScreenConnect. This process is a child process of the ScreenConnect client process.
5.  The attacker uses `cmd.exe` to execute malicious commands, such as downloading and executing a malicious payload.
6.  Alternatively, the attacker spawns `powershell.exe` with encoded commands or commands to download and execute malicious payloads from a remote server.
7.  The attacker establishes persistence by creating a scheduled task using `schtasks.exe` or creates a new service using `sc.exe`.
8.  The attacker uses tools like `net.exe` to modify user accounts or privileges to maintain access to the compromised system.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, installation of malware, and establishment of persistent access to the compromised system. This can result in data theft, disruption of services, and further lateral movement within the network. The number of victims and specific sectors targeted varies depending on the attacker's objectives, but the impact can be significant for organizations relying on ScreenConnect for remote support.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect suspicious child processes spawned by ScreenConnect and tune for your environment.
*   Monitor process creation events for ScreenConnect client processes spawning suspicious child processes like `powershell.exe`, `cmd.exe`, `net.exe`, `schtasks.exe`, `sc.exe`, `rundll32.exe`, `mshta.exe`, `certutil.exe`, `wscript.exe`, `cscript.exe`, `curl.exe`, `ssh.exe`, `scp.exe`, `wevtutil.exe`, `wget.exe`, or `wmic.exe` as detailed in the Sigma rules.
*   Enable Sysmon process-creation logging to capture the necessary process execution data to activate the rules above.
*   Review and revoke any unauthorized user accounts or privileges that may have been created or modified using tools like `net.exe` as described in the attack chain.

---
title: Detection of Unauthorized Execution via PowerShell Remoting
slug: 2026-10-powershell-remoting
description: Adversaries leverage Windows PowerShell Remoting for lateral movement and remote command execution, which can be identified by monitoring incoming WinRM connections followed by suspicious child process creation from the wsmprovhost.exe host process.
date: "2026-10-06T17:59:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - execution
  - windows
  - winrm
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: The rule identifies potential lateral movement and remote code execution by monitoring incoming network connections over Windows Remote Management (WinRM) ports.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries abuse [PowerShell remoting] to execute commands remotely on compromised hosts.
    confidence_band: high
rules:
  - title: Detect Suspicious PowerShell Remoting Child Processes
    description: Detects potential lateral movement by identifying network connections to WinRM ports followed by the spawning of suspicious child processes from wsmprovhost.exe.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1021.006
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Baseline WinRM activity in the environment to identify legitimate administrative traffic.
      owner: SOC
      due: 72h
      evidence: False positive analysis notes the need to baseline environment noise.
  hunt_leads:
    - lead: Search for wsmprovhost.exe spawning processes other than known management binaries.
      technique_id: T1021.006
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Rule description suggests investigating process trees where wsmprovhost.exe spawns unexpected child processes.
---

Windows PowerShell Remoting is a powerful administrative feature that enables the execution of PowerShell commands on remote systems via the Windows Remote Management (WinRM) protocol. While essential for system administration, this dual-use capability is frequently abused by threat actors to perform lateral movement and remote code execution across a network. Attackers typically authenticate to a target host and initiate commands that result in the spawning of child processes under the context of the WinRM host process, wsmprovhost.exe. Because WinRM is a common source of benign administrative noise, defenders must baseline expected management traffic - specifically connections on TCP ports 5985 and 5986 - and investigate anomalous process trees to differentiate legitimate operational activity from unauthorized adversary behavior.

## Attack Chain

1. Attacker gains initial access to a source machine within the target environment.
2. Attacker identifies a target host configured to accept PowerShell Remoting connections.
3. Attacker establishes a remote session to the target host using stolen or brute-forced credentials over WinRM (TCP/5985 or 5986).
4. The WinRM service on the target host spawns wsmprovhost.exe to host the remote session.
5. Attacker executes a command or script via the established remote session.
6. The wsmprovhost.exe process spawns a child process (e.g., cmd.exe, powershell.exe, or other binaries) to carry out the requested command.
7. Attacker achieves remote code execution or proceeds to further lateral movement stages.

## Impact

Successful abuse of PowerShell Remoting allows threat actors to execute arbitrary commands, exfiltrate data, or deploy secondary payloads across an internal network. Unauthorized remote access often leads to privilege escalation and widespread compromise of domain-joined Windows endpoints and servers.

## Recommendation

1. Enable logging for process creation (Sysmon Event ID 1) and network connections (Sysmon Event ID 3) on all Windows endpoints.
2. Baseline network traffic destined for ports 5985 and 5986 to identify authorized administrative source IPs and establish a whitelist.
3. Deploy the provided detection logic to monitor for wsmprovhost.exe spawning non-standard or unexpected child processes.
4. Investigate alerts by correlating the network connection timestamp with the subsequent process creation events to verify user authorization.
5. Implement strict access control lists and restrict WinRM access to specific jump hosts or management workstations.

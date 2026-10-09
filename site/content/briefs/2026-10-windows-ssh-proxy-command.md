---
title: Abuse of Windows SSH ProxyCommand and LocalCommand for Code Execution
slug: 2026-10-windows-ssh-proxy-command
description: Attackers are abusing Windows SSH configuration features 'ProxyCommand' and 'LocalCommand' to execute arbitrary scripts and establish command-and-control channels via living-off-the-land binaries.
date: "2026-10-09T12:22:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - execution
  - command-and-control
  - ssh
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: The detection identifies potential abuse of SSH ProxyCommand or LocalCommand by monitoring for suspicious process execution patterns like powershell, mshta, or wscript.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: This technique can be used by attackers to execute arbitrary commands through SSH proxy configurations, potentially enabling command and control activities.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The detection focuses on commonly abused Windows scripting engines and web requests that may indicate malicious activity when spawned through SSH proxy commands.
    confidence_band: high
rules:
  - title: Detect Suspicious SSH ProxyCommand or LocalCommand Child Processes
    description: Detects instances where ssh.exe spawns suspicious child processes like PowerShell, mshta, or wscript via ProxyCommand or LocalCommand arguments.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1105
      - T1572
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
    - action: Deploy the Sigma rule to monitor for suspicious SSH child processes
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific process-creation patterns and command-line arguments to match.
  hunt_leads:
    - lead: Search for instances of ssh.exe spawning powershell, mshta, or wscript
      technique_id: T1572
      data_needed:
        - Process creation logs (Event ID 1)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source documents this as an indicator of SSH proxy abuse.
---

Adversaries are increasingly leveraging built-in Windows SSH client functionality as a mechanism for executing arbitrary commands, bypassing traditional security controls. By manipulating the 'ProxyCommand' or 'LocalCommand' arguments within an SSH connection string, attackers can trigger the automatic execution of child processes when an SSH session is initiated or a proxy connection is established. This technique is particularly effective for 'Living off the Land' (LotL) operations, as it abuses legitimate, trusted binaries to execute malicious payloads or scripting engines like PowerShell, mshta, or wscript.

This activity has been observed in various contexts, including command-and-control (C2) operations and the delivery of secondary payloads. By embedding commands within the SSH configuration, attackers effectively mask their activity under the guise of legitimate SSH traffic and process execution, making it difficult for defenders to distinguish malicious intent without deep visibility into parent-child process relationships and process command-line arguments.

## Attack Chain

1. Attacker gains access to a Windows host where the SSH client (ssh.exe) is installed and available.
2. Attacker prepares a malicious SSH configuration or command string containing 'ProxyCommand' or 'PermitLocalCommand=yes' combined with a 'LocalCommand' payload.
3. Attacker executes 'ssh.exe' using the malicious configuration string via command line, script, or a scheduled task.
4. The 'ssh.exe' process initializes and evaluates the provided command-line arguments.
5. 'ssh.exe' spawns a child process corresponding to the specified 'ProxyCommand' or 'LocalCommand' (e.g., powershell.exe, mshta.exe, or cscript.exe).
6. The child process executes the embedded malicious payload, such as a web request to retrieve a secondary stage or a local script execution.
7. Final objective is achieved, such as C2 beaconing, persistence, or data exfiltration.

## Impact

Successful exploitation allows for unauthorized code execution with the privileges of the user running the SSH client. This technique facilitates command-and-control communication, the execution of memory-resident malware, and the obfuscation of post-exploitation activities. It has been associated with ransomware campaigns and other malicious operations that rely on native binaries to evade detection.

## Recommendation

Prioritize the monitoring of SSH process spawning behavior to identify suspicious child processes.

* Deploy the provided Sigma rule to your SIEM/EDR to detect suspicious child processes spawned by ssh.exe.
* Enable EDR process-creation logging (e.g., Sysmon Event ID 1) across all workstations and servers.
* Audit SSH configuration files and command-line usage patterns to identify unauthorized use of 'ProxyCommand' or 'LocalCommand' features.
* Use the Splunk Common Information Model (CIM) to ensure process telemetry is correctly normalized for efficient detection.

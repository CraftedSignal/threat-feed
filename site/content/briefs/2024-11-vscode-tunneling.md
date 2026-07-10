---
title: VScode Remote Tunnel Abuse for Command and Control
slug: 2024-11-vscode-tunneling
description: Adversaries are leveraging the VScode remote tunnel feature to establish unauthorized access and control over Windows systems, potentially enabling command and control activities via disguised legitimate software.
date: "2024-11-14T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vscode
  - remote-access
  - command-and-control
  - windows
vendors:
  - Microsoft
products:
  - Visual Studio Code
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Tools
references:
  - https://badoption.eu/blog/2023/01/31/code_c2.html
  - https://code.visualstudio.com/docs/remote/tunnels
rules:
  - title: Detect VScode Tunnel Execution
    description: Detects the execution of VScode with the 'tunnel' command-line option, indicating a potential attempt to establish a remote tunnel for command and control.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect VScode Tunnel Process Spawning Unusual Child Process
    description: Detects VScode tunnel process spawning unusual child processes, which could indicate command execution.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The VScode remote tunnel feature enables developers to connect to remote environments. However, adversaries can exploit this to establish unauthorized access and control over systems. This technique involves executing the VScode portable binary with the "tunnel" command-line option, potentially establishing a covert communication channel. This activity can be masked as legitimate software usage, making it difficult to detect. This technique allows threat actors to bypass traditional network security measures and establish persistent remote access to compromised systems. The targeted systems are typically Windows-based development environments. Defenders should prioritize detecting and preventing the abuse of legitimate remote access tools.

## Attack Chain

1. Initial Access: The attacker gains initial access to a Windows system, possibly through phishing or exploiting a known vulnerability.
2. Tool Deployment: The attacker deploys a portable version of VScode onto the compromised system.
3. Tunnel Configuration: The attacker executes VScode with the `tunnel` command-line option, configuring a remote tunnel to a GitHub or a remote VScode instance.
4. Session Establishment: The VScode instance on the compromised system initiates a connection to the attacker-controlled server, using the established tunnel.
5. Command Execution: The attacker can now execute commands remotely on the compromised system via the tunnel.
6. Lateral Movement: Using the compromised system as a pivot, the attacker attempts to move laterally to other systems within the network.
7. Data Exfiltration: The attacker exfiltrates sensitive data from the compromised network through the established VScode tunnel.
8. Persistence: The attacker establishes persistence by creating a scheduled task or modifying registry keys to ensure the VScode tunnel is automatically restarted upon system reboot.

## Impact

Successful exploitation of the VScode remote tunnel feature can lead to unauthorized access to sensitive data, lateral movement within the network, and persistent command and control over compromised systems. This can result in data breaches, financial losses, and reputational damage. The lack of readily available IOCs and the legitimate nature of VScode makes detection challenging.

## Recommendation

*   Deploy the Sigma rule "Detect VScode Tunnel Execution" to your SIEM to detect suspicious VScode tunnel activity based on command-line arguments.
*   Enable Sysmon process creation logging to capture the command-line arguments used when executing VScode.
*   Monitor network connections for unusual traffic patterns originating from VScode processes, particularly connections to GitHub or other remote VScode instances.
*   Implement application control policies to restrict the execution of unauthorized VScode instances and prevent the use of the `tunnel` command-line option.

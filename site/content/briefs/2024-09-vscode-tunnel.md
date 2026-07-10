---
title: Detection of Suspicious VScode Remote Tunnel Usage
slug: 2024-09-vscode-tunnel
description: This brief details the detection of potential command and control activity through the suspicious use of the VScode remote tunnel feature, which allows attackers to establish unauthorized remote access to systems.
date: "2024-09-09T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - vscode
  - remote-access
  - windows
vendors:
  - Microsoft
products:
  - Visual Studio Code
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
references:
  - https://badoption.eu/blog/2023/01/31/code_c2.html
  - https://code.visualstudio.com/docs/remote/tunnels
rules:
  - title: Detect VScode Tunnel Execution
    description: Detects the execution of VScode with the 'tunnel' command-line argument, indicating a potential attempt to establish a remote tunnel for command and control.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect VScode Tunnel Executables in Suspicious Paths
    description: Detects VScode tunnel executables running from ProgramData, Users\Public, or Windows\Debug, which is highly unusual.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule detects the execution of the VScode portable binary with the `tunnel` command line option, indicating a potential attempt to establish a remote tunnel session to GitHub or a remote VScode instance. While VScode's remote tunnel feature is designed for legitimate remote development, adversaries can abuse it to gain unauthorized access and control over systems. This detection focuses on identifying suspicious command-line arguments and process behaviors associated with VScode's tunnel functionality, flagging potential misuse indicative of command and control activities. The rule covers Windows systems and leverages process data from various sources including Elastic Endgame, Sysmon, and Microsoft Defender for Endpoint. The activity was observed starting around 2024-09-09.

## Attack Chain

1.  The attacker gains initial access to a Windows system, potentially through phishing or exploiting a software vulnerability.
2.  The attacker downloads a portable version of VScode to the compromised system, avoiding typical installation procedures.
3.  The attacker executes VScode with the `tunnel` command-line argument, initiating an attempt to establish a remote tunnel.
4.  The attacker uses arguments like `--accept-server-license-terms` to bypass prompts and streamline the tunnel setup.
5.  VScode establishes a connection to a remote server, potentially GitHub or a malicious VScode instance under the attacker's control.
6.  The attacker uses the established tunnel to remotely execute commands, transfer files, or perform other malicious activities on the compromised system.
7.  The attacker maintains persistent access through the established tunnel, allowing them to remotely monitor and control the system over time.

## Impact

Successful exploitation via VScode remote tunnel can lead to unauthorized remote access, data exfiltration, command execution, and persistent system compromise. This could impact any Windows system within the environment if an attacker leverages this legitimate tool for malicious purposes. If successful, the attacker gains complete control over the compromised system, potentially leading to sensitive data leaks and further propagation within the network.

## Recommendation

*   Deploy the Sigma rule "Detect VScode Tunnel Execution" to your SIEM and tune for your environment to identify potential malicious use of VScode's tunnel feature.
*   Investigate any process executions flagged by the "Detect VScode Tunnel Execution" Sigma rule, focusing on command-line arguments and process behaviors.
*   Enable Sysmon process-creation logging to enhance visibility into process executions and command-line arguments, which is crucial for the "Detect VScode Tunnel Execution" Sigma rule.
*   Monitor network connections from VScode processes for unusual or unauthorized communication patterns, supplementing the process-based detections.

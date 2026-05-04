---
title: Detection of VScode Remote Tunneling for Command and Control
slug: 2024-09-vscode-tunnel
description: The rule detects the execution of the VScode portable binary with the tunnel command line option, potentially indicating an attempt to establish a remote tunnel session to Github or a remote VScode instance for unauthorized access and command and control.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - vscode
  - remote-access-tools
  - windows
vendors:
  - Microsoft
  - GitHub
  - Elastic
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - Sysmon
  - Visual Studio Code
affected_os:
  - Windows
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
    description: Detects the execution of VScode with the tunnel command-line argument, potentially indicating malicious remote access.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect VScode Tunnel Child Process
    description: Detects child processes spawned by VScode when establishing a tunnel connection.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying the misuse of Visual Studio Code's (VScode) remote tunnel feature to establish unauthorized access or control over systems. While the VScode remote tunnel feature is designed to allow developers to connect to remote environments seamlessly, attackers can abuse this functionality for malicious purposes. The rule specifically looks for the execution of the VScode portable binary with the "tunnel" command-line option, which is indicative of an attempt to establish a remote tunnel session to either GitHub or a remote VScode instance. Successful exploitation can lead to command and control capabilities, allowing attackers to remotely manage and compromise the affected system. The rule aims to detect this suspicious behavior by monitoring process execution and command-line arguments.

## Attack Chain

1.  The attacker gains initial access to the target system through unspecified means.
2.  The attacker downloads a portable version of Visual Studio Code (VScode) onto the compromised system.
3.  The attacker executes the VScode binary with the `tunnel` command-line argument to initiate a remote tunnel session.
4.  The attacker specifies additional arguments such as `--accept-server-license-terms` to bypass license agreement prompts.
5.  The VScode tunnel attempts to establish a connection to a remote server, potentially a GitHub repository or a remote VScode instance controlled by the attacker.
6.  If successful, the tunnel creates a persistent connection, allowing the attacker to execute commands and transfer files.
7.  The attacker uses the established tunnel to remotely access the compromised system, enabling them to perform malicious activities such as data exfiltration or lateral movement.
8.  The attacker maintains persistent access through the established tunnel, allowing for long-term command and control of the compromised system.

## Impact

Successful exploitation allows attackers to establish a persistent command and control channel, enabling them to remotely manage the compromised system. This can lead to data theft, deployment of ransomware, or further lateral movement within the network. While the number of potential victims and specific sectors targeted are not explicitly stated, the widespread use of VScode makes a wide range of organizations vulnerable.

## Recommendation

*   Deploy the "Attempt to Establish VScode Remote Tunnel" rule to detect suspicious VScode tunnel activity in your environment.
*   Enable Sysmon process-creation logging to capture the necessary process execution data.
*   Investigate any alerts triggered by the rule, focusing on the command-line arguments and process behaviors to confirm malicious intent.
*   Monitor network connections originating from VScode processes for unusual or unauthorized connections to external servers.
*   Review and whitelist legitimate uses of VScode's tunnel feature by authorized developers to reduce false positives.

---
title: Command Prompt Network Connection Activity
slug: 2024-01-cmd-network-connection
description: Detection of command prompt activity initiating network connections can indicate suspicious or malicious behavior, potentially leading to command and control or data exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-prompt
  - network-connection
  - execution
vendors:
  - Microsoft
products:
  - Microsoft Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Application Layer Protocol
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_command_prompt_connecting_to_the_internet.toml
rules:
  - title: Detect Command Prompt Making Outbound Connections
    description: Detects command prompt making outbound connections, which may indicate command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious DNS Queries from cmd.exe
    description: Detects DNS queries initiated by cmd.exe that resolve unusual or malicious domains.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1568.002
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

Adversaries often leverage the command prompt (cmd.exe) to execute commands, download payloads, and establish network connections. This activity can be part of a larger attack campaign involving malware deployment, reconnaissance, or data exfiltration. Detecting network connections initiated by cmd.exe can provide valuable insights into potentially malicious actions, especially when combined with other suspicious indicators. This type of activity is not inherently malicious but warrants closer inspection when observed in conjunction with other anomalies.

## Attack Chain

1.  Initial Access: An attacker gains initial access through various means (e.g., compromised credentials, software vulnerability).
2.  Command Execution: The attacker executes cmd.exe to perform subsequent actions on the system.
3.  Network Connection: cmd.exe initiates a network connection using tools like `ping`, `nslookup`, or `powershell` (via cmd.exe) to resolve domain names or communicate with external servers.
4.  Data Exfiltration: The attacker uses cmd.exe in conjunction with other tools (e.g., `curl`, `bitsadmin`, `certutil`) to download or upload data to a remote server.
5.  Command & Control: cmd.exe is used to execute commands received from a command and control (C2) server, allowing the attacker to remotely control the compromised system.
6.  Lateral Movement: The attacker leverages cmd.exe to perform actions on other systems within the network, such as copying files or executing commands remotely via `PsExec`.
7.  Persistence: The attacker establishes persistence by creating scheduled tasks or modifying registry keys using cmd.exe.

## Impact

Successful exploitation can lead to data theft, system compromise, and further propagation of malware throughout the network. Attackers can use the compromised system as a foothold to access sensitive information, disrupt business operations, or launch attacks against other targets. While the single network connection from `cmd.exe` may not be particularly damaging in isolation, repeated use or connections to known bad IPs can be.

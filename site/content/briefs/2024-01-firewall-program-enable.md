---
title: Firewall Allowed Program Enable
slug: 2024-01-firewall-program-enable
description: Detection of firewall rule modification to allow specific application execution, potentially bypassing restrictions and enabling unauthorized network communication.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - firewall
  - defense-evasion
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/firewall_allowed_program_enable.yml
  - https://app.any.run/tasks/ad4c3cda-41f2-4401-8dba-56cc2d245488/
rules:
  - title: Firewall Program Allowed via Netsh
    description: Detects when a program is allowed through the firewall using netsh.exe.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Firewall Program Allowed via PowerShell
    description: Detects when a program is allowed through the firewall using PowerShell.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Firewall Program Allowed via CMD
    description: Detects when a program is allowed through the firewall using CMD
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection focuses on identifying attempts to modify firewall rules to allow specific programs to execute, which is a common tactic used by attackers to bypass network restrictions. The detection leverages Endpoint Detection and Response (EDR) data, specifically process creation events and their associated command-line arguments, to identify suspicious firewall rule changes. By monitoring for processes that enable or add firewall rules to allow programs, security teams can identify potential unauthorized network communication attempts. This activity is significant as it may indicate an attacker attempting to establish persistence, escalate privileges, or execute arbitrary code within the targeted environment. The activity has been associated with threat actors deploying ransomware such as BlackByte and Medusa, as well as remote access trojans like NjRAT and PlugX.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a system through various means, such as exploiting a vulnerability or using stolen credentials.
2.  Privilege Escalation: The attacker escalates privileges to gain administrative access to the system.
3.  Defense Evasion: The attacker attempts to disable or modify security controls to evade detection.
4.  Firewall Modification: The attacker executes a command to modify the firewall rules to allow a specific program to communicate over the network. This is often achieved using command-line tools.
5.  Program Execution: The attacker executes a malicious program that is now allowed to communicate over the network due to the modified firewall rule.
6.  Lateral Movement: The attacker uses the compromised system to move laterally to other systems within the network.
7.  Command and Control: The attacker establishes a command and control channel to communicate with the compromised system.
8.  Exfiltration/Ransomware: The attacker exfiltrates sensitive data or deploys ransomware to encrypt the system's data.

## Impact

Successful modification of firewall rules can lead to significant security breaches. Attackers can use this technique to bypass network restrictions, allowing them to execute malicious code, establish persistence, and move laterally within the network. This can lead to data exfiltration, ransomware deployment, and other damaging activities. Systems affected by BlackByte, Medusa, NjRAT, and PlugX have all used this technique to further their goals on a compromised network.

## Recommendation

*   Enable Sysmon process-creation logging (Event ID 1) and Windows Event Log Security (Event ID 4688) to capture the necessary data for this detection.
*   Deploy the Sigma rule `Firewall Allowed Program Enable` to your SIEM and tune for your environment.
*   Investigate any identified instances of firewall rule modifications to determine if they are legitimate or malicious.
*   Monitor for processes with the terms "*firewall*", "*allow*", "*add*", and "*ENABLE*" in their command line, as described in the `search` query.

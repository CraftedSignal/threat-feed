---
title: Firewall Disabled via Netsh Command
slug: 2024-01-disabling-firewall-netsh
description: Detection of Windows Firewall being disabled via the `netsh` command, potentially exposing the system to external threats and unauthorized communication.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - endpoint
  - windows
vendors:
  - Microsoft
products:
  - Windows Firewall
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html
rules:
  - title: Detect Firewall Disabled via Netsh
    description: Detects when the Windows Firewall is disabled via the netsh command.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Firewall Rule Added via Netsh
    description: Detects when a firewall rule is added via the netsh command, which may be a precursor to disabling the firewall.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This alert identifies instances where the Windows Firewall is disabled using the `netsh` command-line utility. Attackers may disable the firewall to allow unrestricted network communication for malware, lateral movement tools, or data exfiltration processes. The detection focuses on command-line executions containing keywords such as "firewall," "off," or "disable," observed through Endpoint Detection and Response (EDR) telemetry. The absence of a properly configured and enabled firewall increases the attack surface of the host and allows malicious actors to bypass default operating system protections. This technique can be used by various threat actors, including ransomware groups such as BlackByte, to facilitate their objectives within a compromised environment.

## Attack Chain

1. An attacker gains initial access to a system, potentially through phishing or exploiting a vulnerability.
2. The attacker executes `netsh.exe` with administrative privileges.
3. The command-line includes arguments to disable the Windows Firewall, such as `netsh advfirewall firewall set allprofiles state off`.
4. The system's firewall rules are deactivated, allowing all inbound and outbound network traffic.
5. Malware or other malicious tools are deployed on the compromised system.
6. The malware establishes a connection to its command and control (C2) server without firewall restrictions.
7. The attacker performs lateral movement within the network, exploiting the lack of firewall protection on the initial host.
8. Sensitive data is exfiltrated from the compromised network to an external location.

## Impact

Successful disabling of the Windows Firewall can lead to complete compromise of the affected system. This may allow for unrestricted malware execution and communication, leading to data exfiltration, ransomware deployment, and lateral movement within the network. Organizations may experience data breaches, financial losses, and reputational damage. The BlackByte ransomware group, among others, uses this technique to further their campaigns, highlighting the severity and potential widespread impact.

## Recommendation

*   Deploy the Sigma rule "Detect Firewall Disabled via Netsh" to your SIEM and tune for your environment to detect this specific activity.
*   Enable process creation logging with command-line arguments for `netsh.exe` using Sysmon or Windows Event Logging to provide necessary data for the detection.
*   Investigate any instances of `netsh.exe` being executed with firewall-related arguments, especially those originating from unusual parent processes.
*   Implement the provided drilldown searches to identify associated user and destination activity for further investigation.
*   Monitor endpoint logs for commands disabling the firewall.

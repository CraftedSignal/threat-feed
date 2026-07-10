---
title: Windows Netsh Tool Used for Firewall Discovery
slug: 2024-01-netsh-firewall-discovery
description: The native Windows `netsh.exe` tool is being abused to discover firewall configurations, potentially to weaken defenses before lateral movement and data exfiltration.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - network-discovery
  - firewall
  - netsh
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Configuration Discovery
references:
  - https://attack.mitre.org/techniques/T1049/
  - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
  - https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/
rules:
  - title: Detect Netsh Usage for Firewall Discovery
    description: Detects the execution of netsh.exe with arguments used to discover or modify firewall configurations.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1049
    data_sources:
      - process_creation
      - windows
  - title: Detect Netsh Firewall Rule Modification
    description: Detects the execution of netsh.exe with arguments used to modify firewall rules.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently use built-in operating system tools to gather information about a target environment. This activity, often referred to as "living off the land," allows them to blend in with normal system activity and avoid detection. This brief focuses on the abuse of `netsh.exe`, a command-line scripting utility for configuring network settings. Specifically, adversaries are using `netsh.exe` to enumerate firewall rules and configurations, which could reveal weaknesses in the system's defenses. Knowing these weaknesses, attackers can then modify the firewall to enable malicious activity or disable the firewall completely. Identifying this type of activity early can help security teams prevent further compromise. This behavior has been observed in post-exploitation scenarios associated with ransomware campaigns like Prestige, and keyloggers like Snake.

## Attack Chain

1.  The attacker gains initial access to the system via an exploit or compromised credentials.
2.  The attacker executes `netsh.exe` with commands to display firewall state (`netsh.exe show state`).
3.  The attacker executes `netsh.exe` to display the firewall configuration (`netsh.exe show config`).
4.  The attacker executes `netsh.exe` to display wireless LAN profiles (`netsh.exe show wlan`).
5.  The attacker parses the output of the `netsh.exe` commands to identify potential vulnerabilities in the firewall configuration.
6.  The attacker modifies firewall rules to allow for lateral movement within the network, often by creating new rules or disabling existing ones.
7.  The attacker leverages the modified firewall settings to establish command and control (C2) channels.
8.  The attacker exfiltrates sensitive data from the compromised system.

## Impact

Successful exploitation can lead to a complete compromise of the target system. The attacker gains unauthorized access to sensitive data, which could result in financial loss, reputational damage, or legal repercussions. The enumeration of network configurations could also allow the attacker to move laterally to other systems on the network, expanding the scope of the attack. This behavior has been observed in Windows Post-Exploitation, Prestige Ransomware, Snake Keylogger, and BlankGrabber Stealer campaigns.

## Recommendation

*   Deploy the "Detect Netsh Usage for Firewall Discovery" Sigma rule to detect the execution of `netsh.exe` with arguments related to firewall configuration and state.
*   Enable Sysmon process creation logging (Event ID 1) to capture command-line arguments for processes.
*   Review and tune the "Windows System Network Connections Discovery Netsh" search included in Splunk ES to reduce false positives in your environment.
*   Monitor for unexpected modifications to firewall rules using Windows Event Logs (Security 4688).

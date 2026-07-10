---
title: MacOS Firewall Configuration Enumeration
slug: 2024-01-macos-firewall-enum
description: Adversaries may enumerate MacOS firewall configurations to identify potential attack surfaces and determine active rules by executing commands like `defaults read /Library/Preferences/com.apple.alf` and `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - macos
  - firewall
  - enumeration
  - discovery
vendors:
  - Apple
products:
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
references:
  - https://www.manpagez.com/man/8/socketfilterfw/
  - https://ss64.com/mac/defaults.html
rules:
  - title: MacOS List Firewall Rules via Defaults
    description: Detects attempts to enumerate macOS firewall rules using the `defaults` command.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - macos
  - title: MacOS Get Firewall Global State via Socketfilterfw
    description: Detects attempts to get the macOS firewall's global state using `socketfilterfw`.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

This threat brief addresses the reconnaissance activity of enumerating macOS firewall configurations. Attackers may use built-in macOS utilities like `defaults` and `socketfilterfw` to gather information about the firewall's status, allowed applications, and configured network flows. While these tools are legitimate and used by administrators, their execution, especially by non-administrative users or during unusual times, can indicate malicious reconnaissance. Specifically, the commands `defaults read /Library/Preferences/com.apple.alf` and `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` provide detailed firewall information. Defenders should monitor for the execution of these commands, focusing on unusual parent processes or user contexts, to detect early-stage intrusion attempts on macOS systems.

## Attack Chain

1.  The attacker gains initial access to a macOS endpoint, potentially through social engineering or exploiting a software vulnerability.
2.  The attacker executes the command `defaults read /Library/Preferences/com.apple.alf` to read the firewall's preferences file, revealing allowed applications and other settings.
3.  The attacker executes the command `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` to determine the global state of the application firewall (enabled/disabled).
4.  The attacker analyzes the output of these commands to identify potential weaknesses in the firewall configuration, such as overly permissive rules or disabled features.
5.  Based on the gathered information, the attacker plans subsequent actions, such as attempting to exploit allowed network services or bypass firewall rules.
6.  The attacker attempts lateral movement by exploiting identified vulnerabilities or misconfigurations to access other systems on the network.

## Impact

Successful enumeration of macOS firewall configurations allows attackers to gain a deeper understanding of the target system's security posture. This knowledge can be leveraged to bypass security controls, identify vulnerable services, and ultimately compromise the system. While this activity itself does not directly cause damage, it significantly increases the likelihood of successful exploitation and data breach.

## Recommendation

*   Enable process execution logging on macOS endpoints using osquery, Endpoint Security framework, or an EDR solution to capture command-line arguments (`data_source`).
*   Deploy the Sigma rule `MacOS List Firewall Rules` to your SIEM and tune the filter `macos_list_firewall_rules_filter` to reduce false positives from legitimate administrative activity (rules).
*   Investigate any execution of `defaults read /Library/Preferences/com.apple.alf` or `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` by non-administrative users or from unexpected parent processes (rules).
*   Review firewall rules regularly to ensure they are correctly configured and do not allow unnecessary network access (overview).

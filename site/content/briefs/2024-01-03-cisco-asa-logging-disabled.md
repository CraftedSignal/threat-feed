---
title: Cisco ASA Logging Disabled via CLI
slug: 2024-01-03-cisco-asa-logging-disabled
description: Detection of disabled logging functionality on a Cisco ASA device via CLI commands, indicating potential defense evasion by adversaries.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - cisco
  - asa
vendors:
  - Cisco
products:
  - Adaptive Security Appliance (ASA) Software
references:
  - https://www.cisco.com/site/us/en/products/security/firewalls/adaptive-security-appliance-asa-software/index.html
  - https://sec.cloudapps.cisco.com/security/center/resources/asa_ftd_continued_attacks
  - https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/63884-config-asa-00.html
  - https://www.cisco.com/c/en/us/td/docs/security/asa/asa922/configuration/general/asa-922-general-config/monitor-syslog.html#ID-2121-000006da
rules:
  - title: Cisco ASA - Logging Disabled via CLI Command
    description: Detects the execution of CLI commands to disable logging on Cisco ASA devices.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - firewall
      - cisco
  - title: Cisco ASA - Logging Disabled Syslog ID
    description: Detects disabling of logging functionality based on specific Cisco ASA syslog message IDs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

This brief focuses on detecting the disabling of logging on Cisco ASA devices. Attackers, including malicious insiders, might disable logging to avoid detection and hide malicious activities within the network. This is achieved by using CLI commands to turn off or clear logging features. This detection is triggered by specific syslog message IDs (111010, 111008) linked to command executions, combined with suspicious commands, like 'no logging,' 'logging disable,' 'clear logging,' or 'no logging host'. The ability to disable logging on a firewall or security appliance represents a substantial attempt at defense evasion, enabling the attacker to operate without generating audit trails.

## Attack Chain

1.  Initial Access: The attacker gains access to the Cisco ASA device's CLI, potentially through stolen credentials or a compromised administrative account.
2.  Authentication: The attacker authenticates to the ASA device, using valid credentials to gain privileged access.
3.  Command Execution: The attacker executes commands via the CLI to modify the logging configuration.
4.  Disable Logging: The attacker uses commands such as `no logging`, `logging disable`, `clear logging`, or `no logging host` to disable logging functionality.
5.  Evasion: With logging disabled, the attacker can perform malicious activities without generating audit logs that would typically be captured by security monitoring systems.
6.  Lateral Movement/Privilege Escalation: The attacker may attempt to move laterally within the network or escalate privileges, taking advantage of the reduced visibility.
7.  Data Exfiltration/System Compromise: The attacker carries out their objectives, such as data exfiltration, system compromise, or network disruption, without being easily detected.

## Impact

If logging is disabled on a Cisco ASA firewall, network defenders lose critical visibility into network traffic and security events. This can lead to delayed detection of security breaches, data exfiltration, and internal reconnaissance activities. Successfully disabling logging allows attackers to operate undetected, significantly increasing the dwell time and potential damage caused by a breach.

## Recommendation

*   Deploy the Sigma rule to detect the execution of commands disabling logging on Cisco ASA devices in your SIEM and tune for your environment.
*   Configure your Cisco ASA devices to forward syslog data, specifically message IDs 111008 and 111010, to your SIEM as outlined in the "how_to_implement" section.
*   Review historical logs for instances of logging being disabled to identify potential past compromises using the provided `cisco_asa` data source.

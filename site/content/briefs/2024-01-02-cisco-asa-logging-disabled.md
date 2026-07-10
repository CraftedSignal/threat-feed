---
title: Cisco ASA Logging Disabled via CLI
slug: 2024-01-02-cisco-asa-logging-disabled
description: Detection of adversaries or malicious insiders disabling logging on a Cisco ASA device via CLI commands, hindering detection and hiding malicious activity.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cisco_asa
  - logging
  - defense_evasion
  - network
vendors:
  - Cisco
products:
  - Cisco ASA
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.cisco.com/site/us/en/products/security/firewalls/adaptive-security-appliance-asa-software/index.html
  - https://sec.cloudapps.cisco.com/security/center/resources/asa_ftd_continued_attacks
  - https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/63884-config-asa-00.html
  - https://www.cisco.com/c/en/us/td/docs/security/asa/asa922/configuration/general/asa-922-general-config/monitor-syslog.html#ID-2121-000006da
rules:
  - title: Cisco ASA Logging Disabled via CLI
    description: Detects the disabling of logging on a Cisco ASA device via CLI commands.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - firewall
      - cisco
  - title: Cisco ASA - Clear Logging Buffer
    description: Detects attempts to clear the logging buffer on a Cisco ASA device, potentially to hide malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

This analytic focuses on detecting the disabling of logging functionality on Cisco ASA devices, a common tactic employed by adversaries and malicious insiders to evade detection and obscure malicious activities. The activity is identified by monitoring Cisco ASA syslog messages associated with command execution. Specifically, the detection triggers on syslog message IDs 111008 and 111010, coupled with the execution of commands indicative of logging manipulation, such as `no logging`, `logging disable`, `clear logging`, or `no logging host`. This tactic is a strong indicator of defense evasion, as disabling logging on security appliances like firewalls significantly reduces the visibility of malicious actions. This is a common post-compromise technique.

## Attack Chain

1.  The attacker gains unauthorized access to the Cisco ASA device, potentially through compromised credentials or exploiting a vulnerability.
2.  The attacker authenticates to the ASA's CLI, possibly using stolen credentials.
3.  The attacker executes a command to disable logging, such as `no logging`, `logging disable`, `clear logging`, or `no logging host`. This action is designed to prevent the recording of their subsequent activities.
4.  The Cisco ASA generates a syslog message with message ID 111008 or 111010, indicating that a command has been executed.
5.  With logging disabled, the attacker performs malicious activities, such as modifying firewall rules, establishing unauthorized VPN connections, or exfiltrating sensitive data.
6.  Because logging is disabled, these malicious activities are not recorded in the ASA's logs, making them difficult to detect.
7.  The attacker attempts to cover their tracks further by clearing any remaining logs or audit trails.

## Impact

Successful disabling of logging can severely impair an organization's ability to detect and respond to security incidents. With logging disabled, malicious activities can go unnoticed, leading to data breaches, system compromise, and financial losses. The impact is magnified by the fact that Cisco ASA devices are often critical components of network security infrastructure. The number of victims can range from single organizations to multiple entities if the attacker is able to compromise multiple ASA devices.

## Recommendation

*   Deploy the Sigma rule `Cisco ASA Logging Disabled via CLI` to your SIEM and tune for your environment to detect attempts to disable logging functionality.
*   Enable and forward Cisco ASA syslog data with message IDs 111008 and 111010 to your SIEM as described in the references and the `how_to_implement` section.
*   Review and enforce strict access control policies for Cisco ASA devices to minimize the risk of unauthorized access.
*   Monitor and alert on changes to logging configurations on Cisco ASA devices to identify suspicious activity.

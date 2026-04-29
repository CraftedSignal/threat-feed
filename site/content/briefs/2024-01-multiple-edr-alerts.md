---
title: Multiple External EDR Alerts by Host
slug: 2024-01-multiple-edr-alerts
description: This rule detects multiple external EDR alerts on the same host, indicating a potential compromise, by analyzing alert data from various EDR solutions like CrowdStrike, SentinelOne, and M365 Defender to identify hosts triggering multiple alerts, enabling prioritization of investigation and response.
date: "2026-04-10T16:27:52Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - threat-detection
  - edr
  - endpoint
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/promotions/external_alerts.toml
rules:
  - title: Multiple External EDR Alerts by Host
    description: Detects hosts with multiple alerts from external EDR solutions, indicating a potential compromise.
    platform: sigma
    severity: high
    tactics:
      - 'domain: endpoint'
      - 'use case: threat detection'
    data_sources:
      - alert
      - elastic
  - title: Suspicious Process Executables Triggering EDR Alerts
    description: Identifies potentially malicious processes associated with EDR alerts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: EDR Alert Triggered by Network Connection to Known Bad IP
    description: Detects network connections to known malicious IPs that trigger EDR alerts.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This detection rule identifies hosts triggering multiple alerts from external Endpoint Detection and Response (EDR) solutions, indicating a potential compromise. It aggregates alert data from sources such as CrowdStrike, SentinelOne, and Microsoft 365 Defender to identify hosts exhibiting a high volume or diversity of security alerts. The rule aims to detect coordinated attacks across multiple hosts, warranting prioritized investigation and response. It prioritizes hosts that trigger a specific threshold of unique alert rules, different alert severities, or have repetitive patterns involving file paths, command lines, or processes. This approach allows security analysts to focus on systems with a higher likelihood of compromise, reducing the time to detect and respond to potential threats.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to a host through various means, such as exploiting a vulnerability or using stolen credentials.
2.  **Malware Deployment:** The attacker deploys malware onto the compromised host. This could be achieved through techniques like phishing or exploiting software vulnerabilities.
3.  **Execution:** The malware executes on the host, initiating malicious activities. This may involve running malicious scripts or binaries.
4.  **Persistence:** The malware establishes persistence on the host to maintain access even after a reboot. This can be achieved by creating scheduled tasks or modifying registry keys.
5.  **Lateral Movement:** The attacker attempts to move laterally to other hosts on the network. This can involve using techniques like pass-the-hash or exploiting network vulnerabilities.
6.  **Command and Control:** The malware establishes communication with a command and control (C2) server to receive instructions and exfiltrate data.
7.  **Privilege Escalation:** The attacker attempts to escalate privileges to gain higher-level access to the system.
8.  **Impact:** The attacker achieves their objective, such as stealing sensitive data or disrupting system operations.

## Impact

A successful attack resulting in multiple EDR alerts can lead to significant disruption and data loss. Depending on the attacker's objectives, this could include the exfiltration of sensitive data, ransomware deployment, or system downtime. The compromise of multiple hosts can indicate a widespread and coordinated attack, potentially affecting a large number of users and systems. Organizations may experience financial losses due to incident response costs, legal liabilities, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Multiple External EDR Alerts by Host` to your SIEM and tune for your environment.
*   Enable logging for CrowdStrike, SentinelOne, and M365 Defender to ensure the Sigma rule can ingest the appropriate logs, as outlined in the rule's query.
*   Prioritize investigation of hosts identified by the rule with high alert counts or diverse alert severities to minimize potential damage.
*   Review and exclude known benign activities from triggering the rule, as detailed in the false positive analysis section of the rule documentation.
*   Correlate alert data with other logs (process creation, network connections, file modifications) to provide better context for detected hosts.
*   Block the C2 domains/IP addresses if they are found to be related to the alerts from the affected hosts.

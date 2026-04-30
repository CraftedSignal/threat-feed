---
title: Multiple Alerts in Different ATT&CK Tactics by Host
slug: 2024-01-multiple-alerts-risky-host
description: This rule uses alert data to identify hosts with multiple alerts across different ATT&CK tactics, indicating a higher likelihood of compromise and enabling analysts to prioritize triage and response based on accumulated risk score.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - threat-detection
  - higher-order-rule
vendors:
  - Elastic
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/multiple_alerts_risky_host_esql.toml
rules:
  - title: High Alert Count with Multiple ATT&CK Tactics
    description: Detects hosts with a high number of alerts spanning multiple ATT&CK tactics, indicating a potentially compromised system.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
  - title: Risky Host Detection via Distinct Alerts
    description: Identifies hosts triggering multiple distinct alerts, indicating a potentially compromised system requiring immediate investigation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: High Risk Score Alert Combination
    description: Flags hosts with a high cumulative risk score from correlated alerts, suggesting a potentially significant compromise.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule, created by Elastic, is designed to identify potentially compromised hosts by aggregating alert data. It focuses on scenarios where a single host triggers multiple alerts associated with different phases of an attack, as defined by the ATT&CK framework. The rule calculates a risk score based on the number and severity of alerts, prioritizing hosts exceeding a defined threshold. By focusing on hosts exhibiting diverse attack tactics, analysts can more effectively triage and respond to complex, multi-stage intrusions. This rule helps filter out noisy alerts such as "Agent Spoofing", "Compression DLL Loaded by Unusual Process", and "Potential PrintNightmare File Modification", and focuses on alerts where `kibana.alert.risk_score` is greater than 0.

## Attack Chain

1. An adversary gains initial access to a host through various methods.
2. The adversary executes malicious code or commands on the host.
3. The attacker establishes persistence to maintain access.
4. The adversary attempts to escalate privileges to gain higher-level control.
5. The attacker performs lateral movement to compromise other systems.
6. The adversary gathers information about the compromised environment.
7. The attacker exfiltrates sensitive data from the network.
8. The attacker achieves their final objective, such as data theft or disruption of services.

## Impact

A successful attack, as identified by this rule, can lead to significant data breaches, system compromise, and operational disruption. Multiple alerts across various tactics suggest a sophisticated and persistent attacker. Prioritizing hosts identified by this rule enables security teams to quickly contain and remediate advanced threats, minimizing potential damage and reducing the overall impact on the organization. Without this detection, analysts might miss critical correlations between seemingly isolated alerts.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to identify potentially compromised hosts based on multiple alerts across different ATT&CK tactics.
*   Investigate any hosts flagged by this rule, correlating the alert data with other logs and telemetry to understand the full scope of the attack.
*   Tune the threshold values in the Sigma rule (distinct rule count, tactic count, risk score) to align with your environment and risk tolerance.
*   Enable logging for process creation, network connections, and file modifications on all hosts to provide sufficient data for the detection rule.
*   Review the "False positive analysis" section of the rule's documentation to identify and exclude known benign activities that may trigger the rule.
*   Use the `Esql.kibana_alert_rule_name_values` field in the rule output to quickly identify the specific alert types triggering the rule.

---
brief_id: brief-2024-01-02-multiple-alerts-risky-host
event_id: brief-2024-01-02-multiple-alerts-risky-host
revision: 2
activity_at: "2024-01-02T12:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:9d685d571efcb461e96badf68b94cc0b02521d1e0e4353c3daa1c1486f2a9f45
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Multiple Alerts in Different ATT&CK Tactics by Host
slug: 2024-01-02-multiple-alerts-risky-host
description: This rule identifies hosts generating multiple alerts across diverse ATT&CK tactics, indicating potential compromise and enabling prioritization of high-risk hosts for triage and response.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - threat-detection
  - higher-order-rule
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/multiple_alerts_risky_host_esql.toml
rules:
  - title: Multiple Alerts in Different ATT&CK Tactics by Host - Sigma
    description: Detects hosts generating multiple alerts across diverse ATT&CK tactics, indicating potential compromise.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Multiple Alerts in Different ATT&CK Tactics by Host - Network
    description: Detects hosts generating multiple alerts across diverse ATT&CK tactics, from network logs.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This Elastic Detection Rule, published on April 10, 2026, is designed to identify potentially compromised hosts by analyzing alerts generated across different phases of an attack. The rule aggregates alerts with populated risk scores, excluding threat_match rules and other noisy alerts such as "Agent Spoofing - Mismatched Agent ID" and "Compression DLL Loaded by Unusual Process." By focusing on hosts with alerts spanning multiple ATT&CK tactics, the rule aims to prioritize triage and response efforts, enabling analysts to quickly identify and address high-risk threats. The rule operates by counting distinct alert rule names, event modules, and threat tactics associated with each host. It calculates a risk score ratio based on the sum of alert risk scores divided by the total number of alerts.

## Attack Chain

1. Initial Access: An attacker gains initial access through an exploit or vulnerability (not specified in the source but inferred from the diversity of later tactics).
2. Execution: The attacker executes malicious code on the host, triggering process creation alerts (e.g., PowerShell or cmd.exe execution).
3. Persistence: The attacker establishes persistence mechanisms, potentially modifying registry keys or creating scheduled tasks, generating registry_set or process_creation events.
4. Privilege Escalation: The attacker attempts to elevate privileges, possibly triggering alerts related to suspicious process execution or service manipulation.
5. Defense Evasion: The attacker attempts to evade defenses, potentially modifying system configurations or disabling security tools, generating file modification or registry modification alerts.
6. Command and Control: The attacker establishes command and control communication with an external server, triggering network connection alerts for unusual processes.
7. Lateral Movement: The attacker attempts to move laterally to other systems on the network, generating authentication or network connection alerts.
8. Impact: The attacker achieves their objective, such as data exfiltration, ransomware deployment, or system disruption (inferred from the multiple tactics observed).

## Impact

Successful exploitation can lead to a full system compromise, allowing attackers to perform a wide range of malicious activities, including data theft, system disruption, and ransomware deployment. The severity of the impact depends on the targeted assets and the attacker's objectives. This rule helps analysts identify compromised hosts early in the attack chain, minimizing potential damage. The rule targets hosts generating multiple alerts, thus indicating a higher chance of severe impact if left unaddressed.

## Recommendation

*   Deploy the Sigma rule to detect hosts generating alerts across multiple ATT&CK tactics, as indicated by distinct counts of rule names and threat tactics (see Sigma rule below).
*   Investigate hosts identified by the Sigma rule, focusing on the specific alerts triggered and correlating them with other log sources (process creation, network connections, file modifications).
*   Tune the rule's thresholds (e.g., `Esql.kibana_alert_rule_name_distinct_count >= 5`, `Esql.threat_tactic_id_distinct_count >= 3`, `Esql.risk_alerts_count_ratio >= 50`) to suit the environment and reduce false positives.
*   Review and exclude known benign activities from triggering the alerts, such as scheduled software updates or system maintenance, based on process names or command-line arguments (see False positive analysis section in the advisory).
*   Enable and monitor relevant logging sources (process creation, network connections, file modifications, registry modifications) to provide the necessary data for the rule to function effectively.
*   Prioritize patching systems generating these alerts, focusing on vulnerabilities that could have allowed initial access and lateral movement.

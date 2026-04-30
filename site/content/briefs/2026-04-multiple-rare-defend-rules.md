---
title: Multiple Rare Elastic Defend Behavior Rules Triggered on Single Host
slug: 2026-04-multiple-rare-defend-rules
description: This rule identifies hosts triggering multiple distinct, globally rare Elastic Defend behavior rules, increasing the likelihood of detecting compromised hosts while reducing false positives.
date: "2026-04-11T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - threat-detection
  - higher-order-rule
  - elastic-defend
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://www.elastic.co/docs/reference/query-languages/esql/commands/inlinestats-by
  - https://github.com/elastic/protections-artifacts/tree/main/behavior
rules:
  - title: Suspicious Process Executing Multiple Times on the Same Host
    description: Detects a process executing multiple times on the same host within a short time frame, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Rare Process Execution Based on Command Line
    description: This rule identifies rare process executions based on command-line arguments, potentially highlighting malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This Elastic Defend rule is designed to detect potentially compromised hosts by identifying those that trigger multiple distinct and rare behavior rules. The rule leverages Elastic's ESQL to analyze endpoint alerts, focusing on behavior rules that are observed on only a single host globally within a specified lookback window. This approach filters out common or widely triggered rules, reducing false positives and highlighting truly anomalous behavior. The rule aims to pinpoint hosts exhibiting unusual activity patterns that may indicate malicious actions, warranting immediate investigation and response. This detection method became generally available in Elastic Stack version 9.3.0.

## Attack Chain

1.  Initial Access: An attacker gains initial access through an unknown vector.
2.  Privilege Escalation: The attacker attempts to elevate privileges on the compromised host.
3.  Execution: The attacker executes malicious code or commands via a script or binary.
4.  Defense Evasion: The attacker attempts to evade detection by disabling security tools or masking their activities.
5.  Lateral Movement: The attacker attempts to move laterally to other systems on the network.
6.  Command and Control: The attacker establishes a command and control channel to communicate with a remote server.
7.  Collection: The attacker gathers sensitive data from the compromised host or network.
8.  Impact: The attacker achieves their final objective, which could include data exfiltration, system disruption, or ransomware deployment.

## Impact

A successful attack can lead to significant data breaches, system compromise, and operational disruption. The targeted sectors are broad, as the rule is designed to detect general anomalous behavior. Depending on the attacker's objectives, the impact could range from data theft and financial loss to complete system shutdown and reputational damage. Hosts identified by this rule should be considered high-priority candidates for incident response and further investigation. The number of victims is dependent on the scope of the intrusion, but this detection aims to limit the spread of the attack by identifying compromised hosts early.

## Recommendation

*   Deploy the provided ESQL rule to your Elastic environment (min. version 9.3.0) to detect hosts triggering multiple rare behavior alerts as indicated by the rule_id `c4f7a2b1-5d8e-4c3a-9b6e-2f1a0d8c7e5b`.
*   Investigate any hosts flagged by this rule, reviewing the associated behavior rule names and process command lines to understand the triggering actions as documented in the rule's `note`.
*   Examine endpoint and network data for the affected host to assess the scope of the compromise and potential persistence mechanisms, per the investigation guidance in the `note`.
*   Document and exclude known-good rule names or hosts from the detection if legitimate single-host tools or scripts trigger multiple rare behavior rules as described in the `note`.
*   Enable Elastic Defend on all endpoints to ensure the availability of the required `endpoint.alerts` data source.

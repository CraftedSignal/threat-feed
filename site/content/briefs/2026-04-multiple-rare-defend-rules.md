---
title: Multiple Rare Elastic Defend Behavior Rules Triggered on Single Host
slug: 2026-04-multiple-rare-defend-rules
description: This rule identifies hosts triggering multiple distinct, globally rare Elastic Defend behavior rules, increasing the likelihood of detecting compromised hosts while reducing false positives.
date: "2026-04-11T12:00:00Z"
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

This Elastic Defend rule is designed to detect potentially compromised hosts by identifying those that trigger multiple distinct and rare behavior rules. The rule leverages Elastic's ESQL to analyze endpoint alerts, focusing on behavior rules that are observed on only a single host globally within a specified lookback window. This approach filters out common or widely triggered rules, reducing false positives and highlighting truly anomalous behavior. The rule aims to pinpoint hosts exhibiting…

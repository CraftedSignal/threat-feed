---
title: LLM-Based Compromised User Triage
slug: 2024-05-llm-compromised-user
description: This rule correlates multiple security alerts involving the same user, analyzes them with an LLM, and flags potentially compromised accounts based on MITRE tactics, geographic anomalies, and multi-host activity, helping analysts prioritize users exhibiting indicators of credential theft or unauthorized access.
date: "2026-04-28T17:17:03Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - 'Domain: Identity'
  - 'Domain: LLM'
  - 'Use Case: Threat Detection'
  - 'Use Case: Identity and Access Audit'
  - 'Resources: Investigation Guide'
  - 'Rule Type: Higher-Order Rule'
vendors:
  - Elastic
products:
  - Elastic Cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.elastic.co/docs/reference/query-languages/esql/esql-commands#esql-completion
  - https://www.elastic.co/security-labs/elastic-advances-llm-security
rules:
  - title: Compromised User Triage - Multiple Failed Logins Followed by Success
    description: Detects a user account with multiple failed login attempts followed by a successful login from the same source IP, potentially indicating credential stuffing or brute-force attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1110.001
    data_sources:
      - authentication
      - windows
  - title: Compromised User Triage - Unusual Process Execution
    description: Detects a user executing a process that is not typically associated with their account, potentially indicating malicious activity or unauthorized access.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This Elastic Security rule, designed for Elastic Cloud deployments 9.3.0 and later, leverages an Elastic Managed LLM to analyze correlated security alerts and identify potentially compromised user accounts. The rule aggregates alerts associated with a single user, examining patterns, MITRE ATT&CK tactic progression, unusual geographic locations, and multi-host activity. The LLM then provides a verdict (compromised, benign, or suspicious) and a confidence score. It aims to reduce analyst workload by surfacing users exhibiting indicators of credential theft or unauthorized access and is intended to be used in conjunction with other detection mechanisms to provide a higher-order analysis.

## Attack Chain

1. Multiple security alerts are triggered across various data sources, such as endpoint activity, network traffic, and authentication logs.
2. Alerts are aggregated and correlated by user.name and user.id, filtering out system accounts and noisy rule types.
3. The rule extracts key alert details, including rule names, threat tactics, techniques, affected hosts, source IPs, and event datasets.
4. An alert summary is constructed, including the user's name, email, number of alerts, distinct rules triggered, affected hosts, time window, and maximum risk score.
5. The LLM analyzes the alert summary, considering multi-host activity, credential access alerts, unusual source IPs, and tactic progression.
6. The LLM provides a verdict (TP, FP, or SUSPICIOUS), a confidence score, and a brief summary explaining the assessment.
7. The rule filters results to surface only compromised or suspicious accounts with a confidence score above 0.7.
8. ECS fields are mapped for timeline visibility and alert exclusion and the analyst is presented with a high-confidence alert.

## Impact

A successful attack using compromised credentials can lead to unauthorized access to sensitive data, lateral movement within the network, and potentially data exfiltration or ransomware deployment. This detection rule helps to quickly identify compromised user accounts, allowing security teams to respond promptly and prevent further damage. The rule reduces the amount of time analysts spend manually triaging alerts and helps them prioritize high-risk users based on an LLM's assessment.

## Recommendation

*   Ensure that your Elastic Cloud deployment is running version 9.3.0 or later to leverage the ES|QL COMPLETION command with Elastic's managed LLM.
*   Review the `Esql.summary` field in the generated alerts to understand the LLM's assessment of why the user was flagged.
*   Investigate alerts where the `Esql.confidence` score is above 0.9, as these indicate strong indicators of compromise.
*   Examine the `Esql.kibana_alert_rule_name_values` and `Esql.kibana_alert_rule_threat_tactic_name_values` to understand which detection rules triggered and what MITRE ATT&CK tactics were observed.
*   Use the provided investigation steps in the rule's note to conduct a thorough investigation, checking for unusual login times, locations, password resets, and MFA changes.

---
brief_id: brief-2024-01-03-llm-attack-chain-triage
event_id: brief-2024-01-03-llm-attack-chain-triage
revision: 1
activity_at: "2024-01-03T10:00:00Z"
title: LLM-Based Attack Chain Triage by Host
slug: 2024-01-llm-attack-chain-triage
description: This rule correlates multiple endpoint security alerts from the same host and leverages an LLM to analyze various endpoint activities, determining if they form a coherent attack chain and prioritizing hosts with corroborated malicious behavior.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
tags:
  - threat-detection
  - llm
  - attack-chain
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
references:
  - https://www.elastic.co/docs/reference/query-languages/esql/esql-commands#esql-completion
  - https://www.elastic.co/security-labs/elastic-advances-llm-security
  - https://www.elastic.co/docs/explore-analyze/ai-features/llm-guides/llm-connectors
rules:
  - title: Suspicious Process Command Line Activity
    description: Detects suspicious process command lines containing potentially malicious keywords.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: DNS Query to Known Malicious Domain
    description: Detects DNS queries to known malicious domains.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - dns_query
      - windows
  - title: Registry Key Modification for Persistence
    description: Detects modifications to registry keys commonly used for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

This Elastic Security rule, released in February 2026 and updated in April 2026, is designed to correlate multiple endpoint security alerts from the same host. It utilizes an Elastic Managed LLM (gp-llm-v2), available in version 9.3.0+, to analyze command lines, parent processes, file operations, DNS queries, registry modifications, module loads, and MITRE ATT&CK tactics progression. The LLM provides a verdict (TP/FP/SUSPICIOUS) with a confidence score and a summary explanation. The goal is to help security analysts prioritize hosts exhibiting corroborated malicious behavior while filtering out benign activity, ultimately improving triage efficiency and response effectiveness. The rule requires a minimum Elastic Stack version of 9.3.0.

## Attack Chain

1. Multiple endpoint security alerts are generated on a single host due to suspicious activities.
2. The rule aggregates these alerts based on the host ID and name, collecting relevant data such as process command lines, parent processes, file paths, DNS queries, and registry modifications.
3. The aggregated data is formatted into a summary string, which serves as context for the LLM.
4. The LLM analyzes the summary, considering factors like suspicious domains, encoded payloads, download-and-execute patterns, and persistence mechanisms.
5. The LLM provides a verdict (TP/FP/SUSPICIOUS), a confidence score, and a short summary explaining its reasoning.
6. The rule filters the results, focusing on findings where the LLM verdict is either "tp" (true positive) or "suspicious" and the confidence score is above 0.7.
7. The LLM summary is mapped to ECS fields like `message` and `event.reason` for timeline visibility.
8. High-confidence TP verdicts trigger immediate host isolation to contain potential compromise, followed by IOC extraction and remediation steps.

## Impact

Successful exploitation can lead to delayed incident response and allow attackers to persist in the environment. The LLM-based approach aims to reduce false positives, allowing analysts to focus on genuine threats. Failing to detect and respond to correlated malicious activity can lead to data breaches, system compromise, and operational disruption. The rule helps analysts prioritize investigation of hosts with multiple, related alerts that suggest an ongoing attack campaign.

## Recommendation

*   Ensure your Elastic Stack is upgraded to version 9.3.0 or later to support the ES|QL COMPLETION command.
*   Deploy the "LLM-Based Attack Chain Triage by Host" rule in your Elastic environment and tune the confidence threshold based on your environment's noise level.
*   Review the investigation guide linked in the rule metadata to understand how to triage and analyze the LLM's verdicts.
*   Configure an LLM connector to utilize the rule with a different LLM provider, as detailed in the [LLM connector documentation](https://www.elastic.co/docs/explore-analyze/ai-features/llm-guides/llm-connectors).
*   Enable endpoint security alerts with sufficient context to ensure the LLM has enough data for accurate analysis (process command lines, parent processes, file paths, DNS queries, registry modifications, module loads).

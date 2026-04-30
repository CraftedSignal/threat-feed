---
title: Newly Observed High Severity Detection Alert in Elastic SIEM
slug: 2024-01-newly-observed-high-severity-detection-alert
description: This rule detects newly observed, low-frequency, high-severity Elastic SIEM detection alerts affecting a single agent, helping prioritize triage and response by highlighting alerts tied to specific detection rules that have not been seen previously for the host.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - threat-detection
  - higher-order-rule
  - elastic-siem
vendors:
  - Elastic
products:
  - SIEM
references:
  - https://www.elastic.co/docs/solutions/security/detect-and-alert/about-detection-rules
rules:
  - title: Newly Observed Process Executable via Command Line
    description: Detects a process executable being called from the command line for the first time, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1057
    data_sources:
      - process_creation
      - windows
  - title: Newly Observed File Path Accessed
    description: Detects a file path being accessed for the first time, which could indicate suspicious file activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - file_event
      - windows
  - title: Newly Observed Network Connection to Uncommon Port
    description: Detects a network connection to an uncommon port for the first time, which could indicate command and control activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This detection rule identifies high-severity alerts within Elastic SIEM that are observed for the first time within a 5-day window. The rule focuses on low-volume, newly observed alerts linked to a specific detection rule. By highlighting these novel alerts, analysts can more effectively prioritize their triage and incident response efforts. This allows security teams to focus on potentially new or evolving threats, rather than being overwhelmed by repeated alerts from well-known attack patterns. The rule aims to reduce alert fatigue and improve the speed and accuracy of threat detection and response. The logic excludes threat_match, machine_learning, and new_terms rule types to minimize noisy alerts.

## Attack Chain

1. A malicious activity occurs on an endpoint or within a network, triggering an Elastic SIEM detection rule with a high severity score (>=73).
2. The Elastic SIEM generates a security alert based on the triggered detection rule. This alert includes details about the event, the affected host, user, and the rule that was triggered.
3. The "Newly Observed High Severity Detection Alert" rule, running every 5 minutes, queries the `.alerts-security.*` indices.
4. The rule filters for alerts that meet specific criteria such as high risk score, excluding certain rule types like "threat_match", "machine_learning", and "new_terms", and excluding endpoint alerts.
5. The rule aggregates alerts by `kibana.alert.rule.name` to identify distinct alerts and calculates the first and last time each alert was observed.
6. The rule determines if the alert is newly observed, defined as the first time it was seen within the last 10 minutes of the rule execution time. This helps filter out alerts that have been occurring for a longer period.
7. The rule further filters for alerts affecting a single agent (`agent_id_distinct_count == 1`) and low alert counts (`alerts_count <= 10`), indicating a potentially novel or isolated incident.
8. The final output highlights the newly observed, low-frequency, high-severity alert, allowing security analysts to investigate and respond accordingly.

## Impact

A successful attack leading to a newly observed high severity alert could indicate a novel or evolving threat that has not been previously seen in the environment. This can lead to a delayed response, potentially allowing the attacker to further compromise systems, exfiltrate data, or cause damage. The impact depends on the specific activity that triggered the underlying high severity alert, but could range from initial access to data breach or ransomware deployment. Failure to prioritize investigation of these new alerts can result in significant financial loss, reputational damage, and operational disruption.

## Recommendation

*   Deploy the Sigma rule `Newly Observed High Severity Detection Alert` to your SIEM and tune for your environment.
*   Use the `Investigation Steps` outlined in the rule's `note` field as a guide to triage newly observed alerts.
*   Review the specific rule investiguation guide for further actions, as referenced in the original Elastic rule's documentation.
*   Configure alerting to notify security analysts immediately upon detection of a `Newly Observed High Severity Detection Alert`.

---
title: Multiple External EDR Alerts by Host
slug: 2024-01-multiple-edr-alerts
description: This rule detects multiple external EDR alerts on the same host, indicating a potential compromise, by analyzing alert data from various EDR solutions like CrowdStrike, SentinelOne, and M365 Defender to identify hosts triggering multiple alerts, enabling prioritization of investigation and response.
date: "2026-04-10T16:27:52Z"
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

This detection rule identifies hosts triggering multiple alerts from external Endpoint Detection and Response (EDR) solutions, indicating a potential compromise. It aggregates alert data from sources such as CrowdStrike, SentinelOne, and Microsoft 365 Defender to identify hosts exhibiting a high volume or diversity of security alerts. The rule aims to detect coordinated attacks across multiple hosts, warranting prioritized investigation and response. It prioritizes hosts that trigger a specific…

---
title: Okta Security Threat Detected
slug: 2024-01-okta-security-threat
description: This alert detects when Okta's ThreatInsight identifies a security threat within an Okta environment, potentially indicating command and control activity.
date: "2024-01-23T12:00:00Z"
severities:
  - medium
tags:
  - identity
  - okta
  - threat-detection
  - attack.command-and-control
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1566
    technique_name: Phishing
references:
  - https://okta.github.io/okta-help/en/prod/Content/Topics/Security/threat-insight/configure-threatinsight-system-log.htm
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta Security Threat Detected
    description: Detects when a security threat is detected in Okta.
    platform: sigma
    severity: medium
    tactics:
      - command-and-control
    data_sources:
      - okta
      - okta
  - title: Okta Brute Force Attack Detected
    description: Detects Okta ThreatInsight flagging a brute force attack attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert focuses on identifying security threats detected by Okta's ThreatInsight. Okta ThreatInsight analyzes traffic patterns and user behavior to identify and block malicious login attempts, brute-force attacks, and other suspicious activities. When ThreatInsight identifies a security threat, it generates a system log event with the eventType `security.threat.detected`. This event serves as a high-level indicator of potential command and control activity within the Okta environment…

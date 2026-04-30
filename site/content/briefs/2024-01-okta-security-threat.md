---
title: Okta Security Threat Detected
slug: 2024-01-okta-security-threat
description: This alert detects when Okta's ThreatInsight identifies a security threat within an Okta environment, potentially indicating command and control activity.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
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

This alert focuses on identifying security threats detected by Okta's ThreatInsight. Okta ThreatInsight analyzes traffic patterns and user behavior to identify and block malicious login attempts, brute-force attacks, and other suspicious activities. When ThreatInsight identifies a security threat, it generates a system log event with the eventType `security.threat.detected`. This event serves as a high-level indicator of potential command and control activity within the Okta environment. Defenders should investigate these alerts promptly to determine the nature and scope of the threat and take appropriate remediation steps. This detection leverages Okta system logs and is relevant for organizations using Okta as their identity provider.

## Attack Chain

1. An attacker attempts to gain unauthorized access to an Okta account, possibly through credential stuffing or brute-force attacks.
2. Okta's ThreatInsight analyzes the login attempt, evaluating factors such as IP address reputation, geographical location, and login frequency.
3. ThreatInsight identifies the login attempt as a security threat based on predefined risk factors.
4. Okta generates a system log event with eventType `security.threat.detected`, recording details of the suspicious activity.
5. The security team receives an alert based on the Sigma rule detecting the `security.threat.detected` event.
6. The security team investigates the alert, examining the associated IP address, user account, and other relevant log data.
7. Based on the investigation, the security team takes appropriate remediation steps, such as blocking the IP address, resetting the user's password, or enabling multi-factor authentication.

## Impact

A successful attack targeting Okta could lead to unauthorized access to sensitive data, account takeover, and disruption of services. The impact of such an attack depends on the level of access granted to the compromised account and the sensitivity of the data accessible through Okta. Successful exploitation can lead to lateral movement within an organization's cloud infrastructure and potentially compromise other critical systems.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `security.threat.detected` events in Okta system logs.
*   Investigate all triggered alerts to determine the nature and scope of the threat.
*   Review Okta's ThreatInsight configuration to ensure it is properly configured and tuned for your environment (references: Okta ThreatInsight documentation).
*   Monitor Okta system logs for suspicious activity, such as unusual login patterns, account lockouts, and password resets (references: Okta system log documentation).
*   Enforce strong password policies and multi-factor authentication to reduce the risk of unauthorized access.

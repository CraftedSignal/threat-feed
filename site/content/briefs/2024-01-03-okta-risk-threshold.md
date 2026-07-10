---
title: Okta User Risk Threshold Exceeded
slug: 2024-01-03-okta-risk-threshold
description: A user exceeding a risk threshold in Okta indicates a potential account compromise, leveraging Enterprise Security's Risk Framework by aggregating risk events from multiple suspicious Okta activities, which may lead to unauthorized access and privilege escalation.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - okta
  - account-takeover
  - risk-framework
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://developer.okta.com/docs/reference/api/event-types
  - https://sec.okta.com/everythingisyes
rules:
  - title: Okta User Risk Score Exceeded
    description: Detects when an Okta user exceeds a predefined risk score based on aggregated suspicious activities.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
      - initial_access
      - persistence
    techniques:
      - T1078
      - T1110
    data_sources:
      - application
      - splunk
  - title: Okta Multiple Failed Login Attempts
    description: Detects multiple failed login attempts for a single user in Okta, potentially indicating a brute-force attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - application
      - okta
rules_count: 2
---

This detection identifies when an Okta user surpasses a predefined risk threshold, suggesting a potential account compromise. It leverages the Risk Framework within Splunk Enterprise Security, specifically aggregating risk events originating from the "Suspicious Okta Activity," "Okta Account Takeover," and "Okta MFA Exhaustion" analytic stories. This correlation highlights user accounts exhibiting multiple malicious TTPs within a 24-hour window. The aggregation of multiple risk factors, such as impossible travel, brute-force attempts, or MFA fatigue, points to a higher likelihood of malicious activity than individual alerts in isolation. Defenders should prioritize investigating users exceeding the risk threshold, as confirmed compromises can lead to significant data breaches, lateral movement, and persistence within the organization's environment.

## Attack Chain

1. Initial Access: Attacker gains initial access to an Okta account, potentially through phishing (T1566) or credential stuffing (T1110).
2. Suspicious Activity: After gaining access, the attacker performs suspicious activities, such as logging in from unusual locations or devices. This triggers the "Suspicious Okta Activity" analytic story.
3. Account Takeover: The attacker successfully takes over the Okta account, potentially changing the password or security settings to maintain control. This triggers the "Okta Account Takeover" analytic story.
4. MFA Exhaustion: The attacker attempts to bypass MFA, possibly through MFA fatigue or other techniques, triggering the "Okta MFA Exhaustion" analytic story.
5. Privilege Escalation: With access to a compromised user account, the attacker attempts to escalate privileges within the Okta environment or connected applications.
6. Lateral Movement: The attacker leverages the compromised Okta account to access other applications and systems within the organization, moving laterally through the environment.
7. Data Access: The attacker gains access to sensitive data stored in applications connected to Okta.
8. Persistence: The attacker establishes persistence within the Okta environment to maintain long-term access.

## Impact

A successful attack following this chain can lead to a full-scale breach, depending on the privileges of the compromised account and the applications connected to Okta. Consequences include unauthorized access to sensitive data, financial loss, and reputational damage. The detection is significant because it pinpoints potentially compromised user accounts exhibiting multiple tactics, techniques, and procedures (TTPs) within a 24-hour period. If confirmed malicious, this activity could indicate a serious security breach.

## Recommendation

*   Enable the "Suspicious Okta Activity", "Okta Account Takeover", and "Okta MFA Exhaustion" analytic stories in Splunk Enterprise Security to populate the Risk Framework data model.
*   Deploy the Sigma rule `Okta User Risk Score Exceeded` to identify users exceeding the risk threshold based on aggregated Okta events.
*   Tune the risk threshold value in the `okta_risk_threshold_exceeded_filter` macro based on your organization's risk tolerance and observed baseline activity.
*   Investigate any users flagged by the `Okta User Risk Score Exceeded` rule, prioritizing those with a high number of MITRE ATT&CK techniques observed as indicated by `mitre_technique_id_count`.
*   Monitor Okta event logs for suspicious activity, such as logins from unusual locations or devices, to identify potential account compromises.
*   Use the drilldown searches to investigate risk events related to specific users.

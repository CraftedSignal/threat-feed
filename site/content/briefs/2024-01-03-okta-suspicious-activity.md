---
title: Okta User Reports Suspicious Activity
slug: 2024-01-03-okta-suspicious-activity
description: A user reporting a suspicious login attempt via Okta's reporting mechanism indicates potential unauthorized access and possible account compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - okta
  - account-takeover
  - t1078.001
vendors:
  - Okta
products:
  - Okta Identity Management
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://help.okta.com/en-us/Content/Topics/Security/suspicious-activity-reporting.htm
rules:
  - title: Okta User Reported Suspicious Activity
    description: Detects when an Okta user reports suspicious activity on their account.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1078.001
    data_sources:
      - webserver
      - okta
  - title: Okta Suspicious Activity Reported - Anomalous Location
    description: Detects suspicious activity reported by a user where the login location is significantly different from the user's typical location.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1078.001
    data_sources:
      - webserver
      - okta
rules_count: 2
---

This brief addresses the scenario where an Okta user reports a login attempt as suspicious. The detection leverages Okta Identity Management logs, specifically the `user.account.report_suspicious_activity_by_enduser` event type. This event signifies that the user has actively identified and flagged a login attempt as potentially malicious. The alert is based on the assumption the user is correctly identifying anomalous activity. This event is critical as it suggests an attacker may have gained access to, or is attempting to gain access to, the user's account. The scope of targeting includes any organization utilizing Okta for identity management. Failure to address reported suspicious activity can lead to data breaches, privilege escalation, and further compromise of the organization's resources.

## Attack Chain

1. **Initial Access Attempt:** An attacker attempts to log in to a user's Okta account, potentially using compromised credentials or a brute-force attack (T1110).
2. **Suspicious Activity Detection (User):** The user notices a login attempt from an unfamiliar location, device, or at an unusual time.
3. **Suspicious Activity Reporting:** The user utilizes Okta's built-in functionality to report the login attempt as suspicious, generating a `user.account.report_suspicious_activity_by_enduser` event.
4. **Alert Triggered:** This event triggers a security alert within the security monitoring system.
5. **Investigation:** Security analysts investigate the reported suspicious activity, examining login logs, user activity, and other relevant data to determine the validity of the report and the extent of any potential compromise.
6. **Containment and Remediation:** If the suspicious activity is confirmed as malicious, the security team takes steps to contain the incident. This may include disabling the user's account, forcing a password reset, and reviewing access privileges.
7. **Credential Review:** The security team reviews other user accounts for similar suspicious activity, implements stronger authentication measures (e.g., MFA), and updates security policies to prevent future incidents.

## Impact

If a reported suspicious activity is not promptly and effectively addressed, an attacker can successfully compromise an Okta user account. This can lead to unauthorized access to sensitive systems and data, potentially resulting in data theft, privilege escalation, lateral movement within the network, and further compromise of the environment. The impact can vary from limited access to a single user's resources to a widespread breach affecting multiple users and systems.

## Recommendation

*   Enable and actively monitor Okta logs for the `user.account.report_suspicious_activity_by_enduser` event type.
*   Deploy the provided Sigma rule to detect reported suspicious activity in your Okta environment. Tune the rule based on your specific environment and user behavior.
*   Implement training programs for associates to effectively recognize and report suspicious activity through Okta's reporting mechanisms.
*   Review Okta's Suspicious Activity Reporting documentation (https://help.okta.com/en-us/Content/Topics/Security/suspicious-activity-reporting.htm) to fully leverage Okta's security features.

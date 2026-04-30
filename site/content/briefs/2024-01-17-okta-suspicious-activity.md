---
title: Okta End-User Reports Suspicious Account Activity
slug: 2024-01-17-okta-suspicious-activity
description: An Okta end-user reports potentially suspicious activity on their account, indicating possible compromise or unauthorized access.
date: "2024-01-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - identity
  - okta
  - suspicious-activity
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://github.com/okta/workflows-templates/blob/1164f0eb71ce47c9ddc7d850e9ab87b5a2b42333/workflows/suspicious_activity_reported/readme.md
rules:
  - title: Okta Suspicious Activity Reported by End-user
    description: Detects when an Okta end-user reports activity by their account as being potentially suspicious.
    platform: sigma
    severity: high
    tactics:
      - resource-development
    techniques:
      - T1586.003
    data_sources:
      - okta
      - okta
  - title: Okta User Password Reset Request Following Suspicious Activity Report
    description: Detects a password reset request shortly after a user reports suspicious activity, potentially indicating an attacker attempting to maintain access.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - resource-development
    techniques:
      - T1555.003
      - T1586.003
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert focuses on detecting when an end-user within an Okta environment reports suspicious activity related to their account. This is a critical indicator that the account may be compromised, or that unauthorized access has occurred. The activity is reported directly by the end-user. While this alert does not directly reveal the method of compromise, it serves as an important signal for security teams to investigate potentially malicious activity. This event triggers from an Okta system log event generated when an end-user utilizes the "report suspicious activity" feature, available in many Okta deployments. Early detection allows security teams to rapidly respond, contain potential damage, and investigate the source of the suspicious activity. This type of self-reporting by end-users can be an invaluable source of threat intelligence within an organization.

## Attack Chain

1.  An attacker gains unauthorized access to an end-user's Okta account, possibly via credential phishing or password reuse.
2.  The attacker attempts to perform actions such as accessing applications, changing profile details, or initiating password resets.
3.  The legitimate end-user observes suspicious activity in their Okta account, such as unfamiliar login locations, unauthorized application access, or unexpected password reset requests.
4.  The end-user utilizes the "report suspicious activity" feature within their Okta account portal.
5.  This action generates an Okta system log event with the eventType `user.account.report_suspicious_activity_by_enduser`.
6.  The detection rule triggers based on this specific Okta log event.
7.  Security analysts investigate the reported activity, examining Okta logs and other relevant data sources.
8.  Based on the investigation, appropriate remediation steps are taken, such as resetting the user's password, revoking active sessions, and blocking any identified malicious IP addresses.

## Impact

A successful account compromise can lead to unauthorized access to sensitive applications and data within the organization. The number of affected users and the impact will depend on the permissions and access granted to the compromised Okta account. This can result in data breaches, financial loss, and reputational damage. Prompt detection of end-user reported suspicious activity allows for rapid incident response, minimizing potential damage.

## Recommendation

*   Deploy the Sigma rule "Okta Suspicious Activity Reported by End-user" to your SIEM to detect when users report suspicious activity, using `eventType: 'user.account.report_suspicious_activity_by_enduser'`.
*   Review Okta system logs for further details surrounding the events that prompted the user report (see references for log details).
*   Implement end-user training programs to educate users on how to identify and report suspicious activity.
*   Investigate all triggered alerts to determine the root cause of the reported suspicious activity.

---
title: Google Workspace Suspended User Account Renewed
slug: 2024-01-google-workspace-suspended-user-renewed
description: Detection of a renewed, previously suspended user account in Google Workspace, potentially indicating unauthorized access or persistence by an adversary.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - google_workspace
  - initial_access
  - persistence
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://support.google.com/a/answer/1110339
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
  - https://support.google.com/a/answer/7061566
  - https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-google_workspace.html
rules:
  - title: Google Workspace Suspended User Account Renewed
    description: Detects when a previously suspended user's account is renewed in Google Workspace.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - webserver
      - linux
  - title: Google Workspace Suspicious Account Manipulation - UNSUSPEND_USER
    description: Detects suspicious account manipulation activity in Google Workspace, specifically the UNSUSPEND_USER event, potentially indicating unauthorized account reactivation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1078
      - T1098
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This alert identifies instances where a user account, previously suspended within a Google Workspace environment, is reactivated. While legitimate administrative actions can trigger this event, adversaries may exploit the account renewal process to regain unauthorized access to the Google Workspace organization. This technique allows them to bypass typical access controls and maintain a valid account for malicious activities. The rule focuses on detecting the `UNSUSPEND_USER` event within Google Workspace admin/audit logs. Google Workspace event logs may have lag times ranging from minutes up to 3 days, defenders should adjust polling intervals to mitigate false negatives.

## Attack Chain

1.  An attacker gains initial access to a privileged Google Workspace account, potentially through compromised credentials or social engineering.
2.  The attacker identifies a suspended user account within the Google Workspace environment.
3.  The attacker renews the suspended user account using the compromised privileged account, triggering the `UNSUSPEND_USER` event.
4.  The renewed account is now active within the Google Workspace environment, allowing the attacker to bypass initial access controls.
5.  The attacker leverages the renewed user account to access sensitive data and resources within Google Workspace.
6.  The attacker may attempt to escalate privileges further from the renewed account.
7.  The attacker maintains persistence by using the renewed account as a long-term backdoor into the organization's Google Workspace environment.

## Impact

A successful account renewal by an attacker can lead to unauthorized access to sensitive data, business disruption, and potential data exfiltration within the Google Workspace environment. The impact can range from minor data breaches to significant operational compromises depending on the permissions and data access of the renewed user account. It's a low severity but important signal that may indicate malicious activity.

## Recommendation

*   Deploy the Sigma rule provided in this brief to your SIEM and tune it for your specific Google Workspace environment.
*   Review the event logs associated with the `UNSUSPEND_USER` action, focusing on the administrator or service account that performed the action, as mentioned in the investigation guide.
*   Implement additional monitoring and alerting on reactivated user accounts to detect any suspicious activity following the account's renewal.
*   Adjust the Google Workspace Filebeat module polling interval to a lower value (e.g., 10 minutes) to reduce the risk of false negatives due to event lag times, as described in the Setup section.
*   Review and update security policies related to account suspension and reactivation to prevent similar incidents in the future.

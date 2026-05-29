---
title: Google Workspace Suspended User Account Renewed
slug: 2026-05-google-workspace-suspended-user-renewed
description: Detection of a renewed suspended user account in Google Workspace, potentially indicating an adversary regaining access to the organization.
date: "2026-05-29T15:15:03Z"
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
references:
  - https://support.google.com/a/answer/1110339
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
rules:
  - title: Google Workspace Suspended User Account Renewed
    description: Detects when a previously suspended user's account is renewed in Google Workspace.
    platform: sigma
    severity: low
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1078.004
      - T1098
    data_sources:
      - webserver
  - title: Google Workspace Suspended User Account Renewed - Event Action
    description: Detects when a previously suspended user's account is renewed in Google Workspace by looking at the event action.
    platform: sigma
    severity: low
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1078.004
      - T1098
    data_sources:
      - webserver
rules_count: 2
---

This detection identifies when a previously suspended user's account is renewed in Google Workspace. Attackers may reactivate suspended accounts to regain unauthorized access, circumventing security measures. Google Workspace administrators use suspended user accounts to remove access while transferring documents and roles before complete account deletion. This rule focuses on the `UNSUSPEND_USER` event within Google Workspace admin logs, aiding analysts in identifying potential misuse of account reactivation and maintaining secure access controls. The rule is configured to run every 10 minutes with a lookback time of 130 minutes to account for Google Workspace event lag times which can range from minutes up to 3 days.

## Attack Chain

1.  An attacker compromises a Google Workspace administrator account or gains unauthorized access.
2.  The attacker identifies a suspended user account within the Google Workspace environment.
3.  Using the compromised administrator account, the attacker executes the `UNSUSPEND_USER` action.
4.  The Google Workspace account is reactivated, granting the attacker access to associated services.
5.  The attacker leverages the renewed account to access sensitive data and resources.
6.  The attacker may then escalate privileges, move laterally, or establish persistence.
7.  The attacker exfiltrates data or performs other malicious activities within the Google Workspace environment.

## Impact

A successful attack could allow unauthorized access to sensitive data within Google Workspace, potentially leading to data breaches, financial losses, or reputational damage. Even though the severity is low, it can be part of a broader attack that leads to sensitive information getting into the wrong hands.

## Recommendation

*   Deploy the Sigma rule `Google Workspace Suspended User Account Renewed` to your SIEM and tune for your environment.
*   Review the event logs for the `UNSUSPEND_USER` action to identify the user account that was renewed and gather details about the timing and context of the action.
*   Investigate the identity of the administrator or service account that performed the `UNSUSPEND_USER` action to determine if the action was authorized.
*   Implement additional monitoring on affected accounts to detect any further suspicious activity.

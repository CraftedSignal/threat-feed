---
title: Google Workspace Device Registration Burst for Single User
slug: 2026-05-google-workspace-device-registration-burst
description: Detects bursts of Google Workspace device registration events for a single user exceeding three distinct device registrations within one minute, indicative of AiTM phishing or stolen OAuth token replay attacks.
date: "2026-05-28T14:10:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - google_workspace
  - device_registration
  - persistence
  - initial_access
  - credential_access
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
references:
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/mobile
  - https://any.run/malware-trends/tycoon/
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_google_workspace_device_registration_burst.toml
rules:
  - title: Detect Google Workspace Device Registration Burst for Single User
    description: Detects a burst of Google Workspace device registration events for a single user, indicating potential AiTM phishing or token replay attacks.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
      - persistence
    techniques:
      - T1078.004
      - T1098.005
      - T1557
    data_sources:
      - device
      - google_workspace
rules_count: 1
---

This detection identifies anomalous Google Workspace device registration activity indicative of adversary-in-the-middle (AiTM) phishing or stolen OAuth token replay attacks. The rule focuses on bursts of `DEVICE_REGISTER_UNREGISTER_EVENT` logs where a single user registers three or more distinct device IDs within a one-minute window. While legitimate session/sync registrations can trigger this event, a high-cardinality burst is rare and suggests malicious activity, such as a phishing kit relaying user sign-ins or token-replay tooling driving multiple sessions against a stolen OAuth refresh token. This activity can lead to account compromise, data exfiltration, and unauthorized access to Google Workspace resources. The rule leverages Google Workspace device logs.

## Attack Chain

1.  The attacker initiates a phishing campaign targeting Google Workspace users (T1566).
2.  The victim clicks a malicious link, leading to an AiTM phishing kit or a credential harvesting page (T1566.001).
3.  The attacker relays the victim's credentials to Google, successfully authenticating and bypassing multi-factor authentication (MFA) if present (T1557).
4.  The attacker's relay or stolen OAuth token replay tooling registers multiple device contexts in rapid succession, generating multiple `DEVICE_REGISTER_UNREGISTER_EVENT` logs with distinct `google_workspace.device.id` values (T1098.005).
5.  The attacker leverages the newly registered devices or replayed tokens to gain persistent access to the victim's Google Workspace account (T1078.004).
6.  The attacker performs unauthorized actions, such as accessing sensitive data, modifying account settings, or sending malicious emails (T1530).

## Impact

Successful exploitation can lead to account compromise, unauthorized access to sensitive data within Google Workspace, and potential business email compromise (BEC). The attacker could exfiltrate data, modify account settings, or use the compromised account to further propagate attacks within the organization. The impact is magnified if the compromised user has elevated privileges or access to critical resources.

## Recommendation

*   Deploy the provided Sigma rule `Detect Google Workspace Device Registration Burst for Single User` to detect suspicious bursts of device registrations (Log Source: Google Workspace Device Logs).
*   Investigate users triggering the rule, focusing on device fingerprint consistency and preceding login events, as described in the rule's `note` section.
*   Cross-reference `logs-google_workspace.login` events for successful logins preceding the burst, examining `source.geo.country_name`, `source.as.organization.name`, and `user_agent.original` for anomalies.
*   Revoke OAuth tokens for affected users (`DELETE /admin/directory/v1/users/<email>/tokens/<clientId>`) if compromise is suspected, as mentioned in the rule's `note` section.

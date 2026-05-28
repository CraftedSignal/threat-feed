---
title: Google Workspace User Sign-in from Atypical Device Type
slug: 2026-05-google-workspace-atypical-device
description: This rule detects when a Google Workspace user authenticates from a device type that hasn't been observed for that user in the past 14 days, potentially indicating account compromise via AiTM kits or stolen OAuth refresh tokens.
date: "2026-05-28T14:09:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - google_workspace
  - persistence
  - account_compromise
  - device_registration
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
references:
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/mobile
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://any.run/malware-trends/tycoon/
rules:
  - title: Google Workspace User Sign-in from Atypical Device Type
    description: Detects Google Workspace user sign-in from a previously unseen device type based on Google Workspace device logs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1078.004
      - T1098.005
    data_sources:
      - device
      - google_workspace
  - title: Google Workspace Token Authorizations Around Atypical Device Registration
    description: Detects OAuth token authorizations for a user shortly after an atypical device registration, potentially indicating unauthorized token minting.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1539
    data_sources:
      - device
      - google_workspace
rules_count: 2
---

This detection rule identifies anomalous Google Workspace device registrations, specifically focusing on deviations from a user's typical device type. It leverages Google Workspace device logs to detect when a user authenticates from a device type (e.g., WINDOWS, MAC, ANDROID, IOS, LINUX) that has not been associated with them within a 14-day historical window. The rule does not flag new physical device enrollments, as the Google Reports API generates fresh device IDs on each event. Instead, it highlights situations where an attacker, using compromised credentials obtained through AiTM kits or stolen OAuth tokens, accesses a Workspace account from a device type different from the user's established pattern. This is a strong indicator of compromise, as these kits often relay sessions through unusual device fingerprints, such as a Windows session for a macOS user, or concurrent sessions from different OS types. Because refresh tokens persist across password resets, focus on token revocation for remediation.

## Attack Chain

1.  Attacker compromises a user's Google Workspace credentials through AiTM phishing or steals an OAuth refresh token.
2.  Attacker uses the stolen credentials or token to authenticate to Google Workspace.
3.  Google Workspace logs a `DEVICE_REGISTER_UNREGISTER_EVENT` with a new `google_workspace.device.id` associated with the session.
4.  The attacker accesses Google Workspace resources like Gmail, Drive, or Calendar.
5.  The attacker may create new OAuth tokens for persistence.
6.  The attacker exfiltrates sensitive data.
7.  The attacker may attempt to move laterally to other cloud resources accessible via the compromised account.
8.  The attacker persists by maintaining access through the stolen credentials and newly created OAuth tokens.

## Impact

A successful attack can result in unauthorized access to sensitive data within Google Workspace, including emails, documents, and calendar information. Attackers can exfiltrate data, escalate privileges, and potentially move laterally to other cloud resources. The compromise can persist even after a password reset due to the nature of OAuth refresh tokens. Affected sectors depend on the victim organization but may include any industry using Google Workspace.

## Recommendation

*   Deploy the Sigma rule "Google Workspace User Sign-in from Atypical Device Type" to detect anomalous device registrations (rule).
*   When an atypical device registration is detected, immediately suspend the user, revoke all OAuth tokens, reset the password, and clear recovery email/phone, as detailed in the rule's "Response and remediation" section.
*   Investigate `logs-google_workspace.login` events for the same user in the 24 hours leading up to the device registration, looking for suspicious ASN, country, and user agent patterns, as described in the rule's "Possible investigation steps" section.
*   Monitor `logs-google_workspace.token` events for `event.action: "authorize"` events around the device registration time to identify newly minted OAuth tokens (rule's "Possible investigation steps").

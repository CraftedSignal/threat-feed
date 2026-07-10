---
title: Okta MFA Disabled by User
slug: 2024-01-09-okta-mfa-disabled
description: Detection of Okta multi-factor authentication (MFA) being disabled by a user account, potentially indicating malicious activity or account compromise and leading to unauthorized access.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - okta
  - mfa
  - account-takeover
  - persistence
vendors:
  - Okta
products:
  - Okta Identity Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1556/
  - https://splunkbase.splunk.com/app/6553
rules:
  - title: Okta MFA Deactivation Detected
    description: Detects when a user disables MFA in Okta
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1556.006
    data_sources:
      - webserver
      - okta
  - title: Okta MFA Disabled by Unfamiliar Source IP
    description: Detects when MFA is disabled from a source IP not usually associated with a user.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1556.006
    data_sources:
      - webserver
      - okta
rules_count: 2
---

This threat brief focuses on the detection of multi-factor authentication (MFA) being disabled for a user within an Okta environment. Attackers with compromised credentials often disable MFA to maintain persistent access to targeted systems and data. The activity is identified through Okta Identity Management Engine (OktaIM2) logs, specifically monitoring for the `user.mfa.factor.deactivate` command. Detecting and responding to this activity is crucial as it can indicate account compromise, insider threats, or misconfigured security policies. Successful exploitation allows bypassing a critical security control, enabling lateral movement, data exfiltration, and other malicious activities. Defenders should prioritize monitoring for MFA deactivation events and correlate them with other suspicious activities.

## Attack Chain

1.  An attacker gains initial access to a valid Okta user account through credential theft or phishing.
2.  The attacker authenticates to the Okta environment using the compromised credentials.
3.  The attacker navigates to the user profile settings within Okta.
4.  The attacker initiates the process to disable MFA for the compromised user account.
5.  The `user.mfa.factor.deactivate` command is executed within Okta, generating an OktaIM2 log event.
6.  The attacker successfully disables MFA for the user account, removing the additional security layer.
7.  The attacker maintains persistent access to applications and resources protected by Okta using only the compromised username and password.
8.  The attacker performs unauthorized actions such as accessing sensitive data, modifying configurations, or escalating privileges.

## Impact

Compromising Okta accounts and disabling MFA can lead to significant damage. Attackers can gain unauthorized access to sensitive data, critical systems, and cloud resources. Organizations using Okta for identity management across numerous applications and services are especially vulnerable. Successful MFA disabling can bypass a significant security control, leading to data breaches, financial losses, and reputational damage. The impact can extend to multiple downstream applications and services integrated with Okta, potentially affecting thousands of users and systems.

## Recommendation

*   Deploy the Sigma rule `Okta MFA Deactivation Detected` to your SIEM and tune it for your environment to detect instances of MFA being disabled (rules).
*   Review Okta user account activity logs for unusual patterns or suspicious behavior around the time of MFA deactivation events (Okta logs).
*   Investigate any detected instances of MFA deactivation to determine if they are authorized or malicious (Okta logs).
*   Implement stricter controls around MFA management, such as requiring administrative approval for MFA deactivation requests (Okta configuration).
*   Monitor source IPs (`All_Changes.src` from search string) associated with MFA deactivation attempts for suspicious or unusual locations.
*   Refer to the Splunk Add-on for Okta Identity Cloud documentation to ensure proper log ingestion and parsing (references).

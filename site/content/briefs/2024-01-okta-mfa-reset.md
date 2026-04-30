---
title: Okta MFA Reset or Deactivation Attempt
slug: 2024-01-okta-mfa-reset
description: An attacker attempts to disable or reset multi-factor authentication (MFA) for a user account in Okta, potentially leading to unauthorized access and account compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - okta
  - mfa
  - credential-access
  - persistence
vendors:
  - Okta
products:
  - Okta Identity Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_mfa_reset_or_deactivated.yml
rules:
  - title: Okta MFA Deactivation
    description: Detects when a user's MFA factor is deactivated in Okta.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - defense-evasion
      - persistence
    techniques:
      - T1556.006
    data_sources:
      - okta
      - okta
  - title: Okta MFA Reset
    description: Detects when a user's MFA is reset in Okta.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - defense-evasion
      - persistence
    techniques:
      - T1556.006
    data_sources:
      - okta
      - okta
rules_count: 2
---

Attackers may attempt to disable or reset MFA to bypass security controls and gain unauthorized access to user accounts. This activity is often part of a broader attack campaign, such as credential stuffing or account takeover. The Okta platform provides detailed logs of user authentication events, including MFA resets and deactivations. Monitoring these events is crucial for detecting and responding to potential account compromise attempts. These attempts can originate from various sources, including compromised administrator accounts or direct attacks on user accounts. The impact of successful MFA bypass can be significant, potentially leading to data breaches, financial loss, and reputational damage.

## Attack Chain

1.  The attacker gains initial access to a user's Okta account, possibly through phishing or credential compromise.
2.  The attacker authenticates to the Okta tenant using the compromised credentials.
3.  The attacker initiates a request to reset or deactivate one or more of the user's MFA factors through the Okta API or web interface.
4.  Okta generates a system log event of type `user.mfa.factor.deactivate` or `user.mfa.factor.reset_all`.
5.  If successful, the attacker can then authenticate without providing the MFA factor, bypassing a critical security control.
6.  The attacker leverages the compromised account to access sensitive applications and data within the Okta environment.
7.  The attacker may perform lateral movement to access other user accounts or systems.
8.  The final objective may include data exfiltration, financial fraud, or other malicious activities.

## Impact

Successful MFA deactivation or reset can lead to complete account takeover. Depending on the compromised user's role and access permissions, this could result in significant data breaches, unauthorized access to sensitive systems, and financial losses. The impact scales with the number of compromised accounts and the sensitivity of the data they can access. This activity targets all sectors relying on Okta for identity and access management.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect suspicious MFA reset or deactivation attempts in Okta logs.
*   Investigate any triggered alerts for `user.mfa.factor.deactivate` or `user.mfa.factor.reset_all` events, as described in the Sigma rule.
*   Review Okta system logs for unusual authentication patterns, focusing on users with recently deactivated MFA factors, as detailed in the Okta API documentation.
*   Implement strict access controls and monitoring for Okta administrator accounts to prevent unauthorized MFA modifications.
*   Educate users about phishing and credential security to reduce the risk of initial access compromise.

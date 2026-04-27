---
title: Okta MFA Reset or Deactivation Attempt
slug: 2024-01-okta-mfa-reset
description: An attacker attempts to disable or reset multi-factor authentication (MFA) for a user account in Okta, potentially leading to unauthorized access and account compromise.
date: "2024-01-03T12:00:00Z"
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

Attackers may attempt to disable or reset MFA to bypass security controls and gain unauthorized access to user accounts. This activity is often part of a broader attack campaign, such as credential stuffing or account takeover. The Okta platform provides detailed logs of user authentication events, including MFA resets and deactivations. Monitoring these events is crucial for detecting and responding to potential account compromise attempts. These attempts can originate from various sources…

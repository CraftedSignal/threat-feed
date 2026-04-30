---
title: Okta User Account Lockout Detection
slug: 2024-01-02-okta-account-lockout
description: Detection of an Okta user account lockout, which may indicate brute-force attempts or other malicious activity targeting user accounts.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - identity
  - account-lockout
  - okta
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta User Account Locked Out
    description: Detects when a user account is locked out due to exceeding the maximum number of sign-in attempts.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - okta
      - okta
  - title: Okta Multiple User Account Lockouts in Short Time
    description: Detects multiple user account lockouts within a short timeframe, possibly indicating a widespread brute-force attack.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - okta
      - okta
rules_count: 2
---

This brief describes detection measures for Okta user account lockouts. An account lockout occurs when a user exceeds the maximum number of permitted failed login attempts, potentially indicating a brute-force attack or other unauthorized access attempts against user accounts. Monitoring for account lockouts is crucial for identifying and mitigating potential security breaches. The rule detects the "Max sign in attempts exceeded" message in Okta logs, which signifies that an account has been locked. Detecting this activity can alert security teams to potential compromise attempts.

## Attack Chain

1.  Attacker attempts to authenticate to Okta with a valid or guessed username.
2.  Attacker provides an incorrect password.
3.  Okta logs the failed authentication attempt.
4.  Attacker repeats steps 2 and 3 multiple times within a defined timeframe.
5.  Okta's account lockout policy is triggered when the maximum number of failed attempts is reached.
6.  Okta logs an event with the `displayMessage` "Max sign in attempts exceeded".
7.  The user account is locked, preventing further login attempts.
8.  Security team investigates the lockout event to determine the root cause and potential impact.

## Impact

A successful account lockout can disrupt legitimate user access and indicate potential malicious activity. Multiple lockouts within a short period may signify a brute-force attack aimed at gaining unauthorized access to sensitive resources. While the lockout itself prevents immediate unauthorized access, it can lead to denial of service and requires investigation to rule out successful credential compromise. The number of impacted users depends on the scope and sophistication of the attack.

## Recommendation

*   Deploy the Sigma rule `Okta User Account Locked Out` to your SIEM to detect account lockout events in Okta logs.
*   Investigate any triggered alerts to determine the cause of the lockout, potentially indicating a brute-force attack (reference: `displayMessage: Max sign in attempts exceeded`).
*   Review and adjust Okta's account lockout policies to balance security and usability based on your organization's risk tolerance.
*   Consider implementing multi-factor authentication (MFA) to mitigate the risk of brute-force attacks and credential compromise.

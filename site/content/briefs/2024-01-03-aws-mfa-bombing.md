---
title: AWS MFA Bombing Attack Attempt
slug: 2024-01-03-aws-mfa-bombing
description: An attacker attempts to bypass MFA by flooding a user with authentication requests on the AWS console, as detected through AWS CloudTrail logs showing multiple failed MFA attempts within a short timeframe.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - mfa
  - credential-access
  - defense-evasion
vendors:
  - AWS
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1621
    technique_name: Multi-Factor Authentication Request Bombing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://attack.mitre.org/techniques/T1621/
  - https://aws.amazon.com/what-is/mfa/
rules:
  - title: Detect AWS Multiple Failed MFA Requests For User
    description: Detects multiple failed MFA requests to an AWS Console for a single user, indicating a potential MFA bombing attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1586.003
      - T1621
    data_sources:
      - webserver
      - aws
  - title: Detect Excessive AWS Console Login Failures
    description: Detects a high volume of failed AWS Console login attempts for a single user, potentially indicating an account brute-force or MFA fatigue attack.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1586.003
      - T1621
    data_sources:
      - webserver
      - aws
rules_count: 2
---

This analytic detects a multi-factor authentication (MFA) bombing attack against an AWS user. The attack involves an adversary attempting to gain unauthorized access to an AWS account by repeatedly triggering MFA prompts for a targeted user. By overwhelming the user with a barrage of MFA requests, the attacker hopes the user will eventually accidentally approve one of the requests, or become desensitized and approve a malicious request without proper scrutiny. The detection relies on AWS CloudTrail logs, specifically examining `additionalEventData` for failed authentication events where MFA was used. A threshold of more than 10 failed MFA prompts within 5 minutes for a single user is considered anomalous and indicative of a potential MFA bombing attack. This activity can lead to full compromise of the AWS environment and access to sensitive data.

## Attack Chain

1.  The attacker obtains valid or leaked AWS usernames targeting a specific user. (T1586.003)
2.  The attacker initiates multiple login attempts to the AWS console using the compromised username.
3.  Each login attempt triggers an MFA request sent to the user's registered device.
4.  The user denies the initial MFA requests due to not initiating the login.
5.  The attacker continues to bombard the user with login attempts in rapid succession.
6.  AWS CloudTrail logs capture each failed login attempt, including details about the MFA usage.
7.  The detection identifies users with more than 10 failed MFA attempts within a 5-minute window.
8.  If successful, the user may eventually accept a malicious MFA request, granting the attacker access to the AWS environment.

## Impact

A successful MFA bombing attack can lead to complete account takeover, giving the attacker full control over the targeted AWS account. This can result in unauthorized access to sensitive data stored in AWS services like S3, RDS, and EC2. The attacker could also launch malicious infrastructure, modify security configurations, or exfiltrate data, leading to significant financial and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune the threshold (mfa_prompts > 10) based on your environment's baseline to reduce false positives.
*   Investigate users triggering the "AWS Multiple Failed MFA Requests For User" detection to determine if the MFA prompts were legitimate or potentially malicious (AWS CloudTrail ConsoleLogin).
*   Implement user training to educate employees about MFA bombing attacks and the importance of scrutinizing each MFA request before approving it.
*   Enforce strong MFA policies, including requiring the use of hardware security keys or biometric authentication for critical accounts.
*   Consider implementing adaptive authentication policies that analyze login behavior and risk scores to dynamically adjust MFA requirements.

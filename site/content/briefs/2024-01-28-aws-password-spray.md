---
title: AWS Password Spraying Attack via Multiple Failed Console Logins
slug: 2024-01-28-aws-password-spray
description: A single source IP attempts to authenticate to the AWS Console against multiple unique user accounts within a short timeframe, indicating a potential password spraying attack.
date: "2024-01-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - password-spraying
  - credential-access
vendors:
  - Amazon Web Services
products:
  - AWS Console
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://attack.mitre.org/techniques/T1110/003/
  - https://www.whiteoaksecurity.com/blog/goawsconsolespray-password-spraying-tool/
  - https://softwaresecuritydotblog.wordpress.com/2019/09/28/how-to-protect-against-credential-stuffing-on-aws/
rules:
  - title: AWS Multiple Failed Console Logins
    description: Detects password spraying attacks against the AWS Console by identifying a high number of failed login attempts from a single IP address.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - webserver
      - linux
  - title: AWS Console Login without MFA
    description: Detects console logins without Multi-Factor Authentication (MFA), which may indicate a security risk.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief focuses on detecting password spraying attacks targeting the AWS Console. The analytic identifies a single source IP address that fails to authenticate against a high number of unique AWS user accounts within a short time window. Password spraying is a technique where attackers attempt to gain unauthorized access by trying common passwords against many accounts. This activity, if successful, can lead to unauthorized access to AWS resources, data breaches, and further malicious activity within the cloud environment. The detection leverages AWS CloudTrail logs and focuses on `ConsoleLogin` events with `failure` status. The threshold for triggering this alert is set to 30 unique accounts within 10 minutes.

## Attack Chain

1. The attacker identifies a list of potential AWS usernames.
2. The attacker sends authentication requests to the AWS Console from a single source IP.
3. Each request attempts to log in to a different user account with a common password.
4. The AWS Console responds with a failure event for each incorrect password attempt. These events are logged in AWS CloudTrail.
5. The attacker repeats steps 2-4 with a different common password.
6. After a series of failed attempts across many accounts, one or more attempts might succeed due to weak passwords.
7. The attacker gains access to an AWS account.
8. The attacker can then perform actions within the AWS environment based on the permissions of the compromised account, such as data exfiltration, resource provisioning, or lateral movement.

## Impact

A successful password spraying attack against AWS can have significant consequences. It can lead to unauthorized access to sensitive data stored in AWS services such as S3 buckets, RDS databases, and EC2 instances. It can also allow attackers to provision new resources within the AWS environment, potentially leading to increased costs and further malicious activity. The impact can range from data breaches and service disruption to complete compromise of the AWS environment. The number of affected users and the severity of the impact depend on the permissions and access levels of the compromised accounts.

## Recommendation

*   Enable and actively monitor AWS CloudTrail logs for `ConsoleLogin` events in all AWS regions to capture failed authentication attempts (data_source).
*   Deploy the Sigma rule `AWS Multiple Failed Console Logins` to identify potential password spraying attacks based on a high number of failed login attempts from a single IP address (rules).
*   Investigate any alerts triggered by the Sigma rule to determine the validity of the suspicious activity and take appropriate remediation steps, such as locking compromised accounts (rules).
*   Enforce strong password policies and multi-factor authentication (MFA) for all AWS user accounts to mitigate the risk of successful password spraying attacks.
*   Consider implementing rate limiting on login attempts to the AWS Console to slow down or prevent password spraying attacks.
*   Review the references provided to understand password spraying attack techniques and how to protect against them (references).

---
title: AWS Management Console Root Login Detected
slug: 2024-01-aws-root-login
description: Detection of a successful AWS Management Console login by the Root user, which is an original identity with unrestricted privileges, indicates a potential security breach requiring immediate investigation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - initial-access
vendors:
  - AWS
products:
  - AWS Management Console
  - AWS CloudTrail
  - AWS Identity and Access Management (IAM)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
rules:
  - title: AWS Management Console Root Login
    description: Detects a successful login to the AWS Management Console by the Root user.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Root User Activity After Login
    description: Detects suspicious API calls made by the AWS root user immediately following a console login event.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The AWS root user possesses unrestricted privileges over all resources within an AWS account, bypassing IAM boundaries. AWS recommends that the root user should not be used for everyday tasks including administrative ones, and root credentials should be locked away for very specific account-level administrative actions. This rule detects successful AWS Management Console logins by the root user (`ConsoleLogin` events with `userIdentity.type: Root` and `event.outcome: Success`). The login event is sourced from AWS CloudTrail logs, providing detailed information about the source IP, user agent, and geolocation of the login attempt. Identifying these logins is critical for maintaining the security and integrity of the AWS environment, as unauthorized access can lead to significant data breaches and system compromises.

## Attack Chain

1.  An attacker gains unauthorized access to the AWS root user credentials, potentially through phishing, credential stuffing, or leaked credentials.
2.  The attacker uses the compromised root credentials to authenticate to the AWS Management Console.
3.  AWS CloudTrail logs the successful `ConsoleLogin` event, including the `userIdentity.type: Root` and `event.outcome: Success`.
4.  The attacker leverages the root user privileges to create new IAM users or roles with elevated permissions, establishing persistence within the AWS environment.
5.  The attacker modifies security policies, such as attaching roles or putting bucket policies, to further escalate privileges and gain access to sensitive resources.
6.  The attacker disables or deletes CloudTrail trails and Security Hub findings suppression in order to cover their tracks.
7.  The attacker accesses and exfiltrates sensitive data stored in S3 buckets or other AWS services.
8.  The attacker may attempt to further compromise other AWS accounts or resources by leveraging the compromised root credentials.

## Impact

A successful compromise of the AWS root user can lead to complete control over the AWS account, resulting in data breaches, financial losses, and reputational damage. The attacker can access and exfiltrate sensitive data, modify or delete critical resources, and disrupt business operations. The severity of the impact depends on the scope of the attacker's actions and the sensitivity of the data stored in the AWS environment. Because the root user has unrestricted privileges, the potential for damage is very high.

## Recommendation

*   Deploy the Sigma rule "AWS Management Console Root Login" to your SIEM using AWS CloudTrail logs to detect successful root user logins.
*   Enable multi-factor authentication (MFA) for the root user account and enforce its usage.
*   Monitor the `source.ip` field in CloudTrail logs for root logins and investigate any unfamiliar IP addresses or locations.
*   Review AWS Identity and Access Management (IAM) configurations to ensure that the root user account is not being used for routine tasks and that appropriate least privilege principles are followed.
*   Investigate follow-on actions in CloudTrail logs immediately after root login events, such as the creation of new IAM users, roles, or policies.
*   Implement automated alerts for any future `userIdentity.type: Root` logins to ensure real-time detection and response.

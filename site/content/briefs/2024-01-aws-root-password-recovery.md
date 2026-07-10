---
title: AWS Root Account Password Recovery Request Detection
slug: 2024-01-aws-root-password-recovery
description: Detection of AWS root account password recovery requests, potentially indicating unauthorized access attempts or legitimate administrative actions requiring verification.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - initial-access
  - password-recovery
vendors:
  - AWS
products:
  - AWS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://web.archive.org/web/20230930161727/https://www.cadosecurity.com/an-ongoing-aws-phishing-campaign/
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
rules:
  - title: Detect AWS Root Password Recovery
    description: Detects password recovery requests for the AWS root user account.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS Root Login After Password Reset
    description: Detects a root user login shortly after a password reset, which could indicate account compromise.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on detecting password recovery requests initiated for the AWS root account. The AWS root account is a highly privileged account, and any unauthorized access or modification attempts should be treated with utmost urgency. The detection mechanism relies on analyzing AWS CloudTrail logs for `PasswordRecoveryRequested` events originating from `signin.amazonaws.com`. These events are exclusive to the root user's "Forgot your password?" workflow, differentiating them from password resets for IAM users or federated identities. Successful detection of a password recovery request necessitates immediate investigation to confirm its legitimacy and prevent potential account compromise. This alert matters because unauthorized root account access can lead to complete control over an organization's AWS infrastructure.

## Attack Chain

1.  **Initial Access:** An attacker attempts to gain access to the AWS account, potentially through phishing, credential stuffing, or other initial access vectors.
2.  **Password Recovery Request:** The attacker initiates the "Forgot your password?" flow for the root account at `signin.amazonaws.com`.
3.  **CloudTrail Logging:** AWS logs the `PasswordRecoveryRequested` event with `event.provider:signin.amazonaws.com` and `event.action:PasswordRecoveryRequested` in CloudTrail.
4.  **Email Notification:** AWS sends a password reset email to the email address associated with the root account.
5.  **Credential Reset:** If the attacker gains access to the email, they can click the password reset link and set a new password for the root account.
6.  **Successful Login:** The attacker uses the newly reset password to log in to the AWS console as the root user. This generates a `ConsoleLogin` event.
7.  **Privilege Escalation:** Once logged in, the attacker can perform administrative actions, such as creating new IAM users with elevated privileges, modifying security policies, or accessing sensitive data.
8.  **Data Exfiltration / Damage:** The attacker exfiltrates sensitive data, deploys malicious infrastructure, or otherwise compromises the environment.

## Impact

A successful attack leveraging a compromised AWS root account can have catastrophic consequences. The root user has unrestricted access to all AWS resources within the account, enabling attackers to exfiltrate sensitive data, disrupt critical services, deploy ransomware, or completely take over the environment. Depending on the organization's size and reliance on AWS, the impact can range from financial losses and reputational damage to complete business disruption. The number of potential victims is vast, as many organizations rely on AWS for their cloud infrastructure.

## Recommendation

*   Deploy the Sigma rule `Detect AWS Root Password Recovery` to your SIEM and tune for your environment to detect password recovery requests.
*   Investigate any triggered alerts from the `Detect AWS Root Password Recovery` rule by validating the source IP address and user agent.
*   Enable multi-factor authentication (MFA) on the root account to prevent unauthorized access, as documented in the AWS documentation link provided in the references.
*   Monitor for subsequent `ConsoleLogin` events after a `PasswordRecoveryRequested` event to detect potential unauthorized logins using the Sigma rule `Detect AWS Root Login After Password Reset`.
*   Review AWS CloudTrail logs for related events such as `CreateAccessKey`, `CreateUser`, or `AttachUserPolicy` shortly after a password recovery request.

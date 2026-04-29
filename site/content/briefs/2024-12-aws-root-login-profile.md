---
title: AWS IAM Login Profile Added for Root
slug: 2024-12-aws-root-login-profile
description: An adversary with temporary root access in AWS may create a login profile for the root account to establish persistent console access, even if the original access keys are rotated or disabled.
date: "2026-04-10T16:27:52Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cloud
  - aws
  - iam
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_iam_create_login_profile_for_root.toml
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/techniques/T1078/004/
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/001/
  - https://attack.mitre.org/tactics/TA0003/
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
rules:
  - title: AWS IAM Login Profile Added for Root
    description: Detects creation of a console login profile for the AWS account root user.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CreateLoginProfile API call
    description: Detects CreateLoginProfile API call by any user
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1098.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This rule detects the creation of a console login profile for the AWS account root user, a highly privileged account. While `CreateLoginProfile` is normally applied to IAM users, when executed from a temporary root session (e.g., via `AssumeRoot`) without specifying a `userName`, the profile is created for the root principal. This activity is especially concerning because it provides persistent access. An attacker gaining temporary root access via STS or credential compromise might exploit this to set a root password. The attacker can then use this new password to log in through the console. This method circumvents traditional access key rotation or disabling and can be employed even after the initial vulnerability is patched. This activity started being tracked on 2024-12-02, defenders need to be aware of this persistence mechanism and promptly investigate any such incidents.

## Attack Chain

1. An attacker gains initial access to an AWS account with sufficient privileges, possibly through compromised credentials or an STS session.
2. The attacker executes the `AssumeRoot` API call to assume the privileges of the root user.
3. The attacker uses the `CreateLoginProfile` API call without specifying a `userName`. This action creates a console login profile directly for the root account instead of an IAM user. The `aws.cloudtrail.request_parameters` will not contain `userName=`.
4. The attacker sets a password for the root account using the `CreateLoginProfile` API. `passwordResetRequired` might be set to `true` or omitted, with omission potentially indicating an attacker-controlled password.
5. The attacker uses the newly created root account password to log in to the AWS Management Console. The event will be logged as a `ConsoleLogin` event.
6. The attacker uses the root account's privileges to create or modify resources, escalate privileges, or exfiltrate data.
7. The attacker maintains persistence by using the console login, even if the initially compromised credentials or temporary session tokens are revoked.
8. The attacker may also create new IAM users or roles with elevated permissions to further solidify their presence.

## Impact

A successful attack can lead to complete control over the AWS environment. The attacker can create, modify, or delete resources; access sensitive data; and disrupt services. Because the root user has unrestricted privileges, the impact is extremely high. There have been no reported victim counts. However, any successful exploitation can have severe impacts including data breaches, financial loss, and reputational damage.

## Recommendation

*   Deploy the Sigma rule "AWS IAM Login Profile Added for Root" to detect unauthorized creation of login profiles for the root account and tune for your environment.
*   Investigate any `CreateLoginProfile` events where `aws.cloudtrail.user_identity.type` is `Root` and `aws.cloudtrail.request_parameters` does not contain `userName=`.
*   Enable CloudTrail, GuardDuty, AWS Config, and Security Hub across all regions for continuous monitoring of root and IAM activity to improve overall visibility.
*   Review IAM policies for least-privilege adherence, focusing on `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, and `iam:CreateAccessKey` permissions.

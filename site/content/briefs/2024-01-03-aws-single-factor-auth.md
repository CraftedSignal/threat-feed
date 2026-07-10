---
title: AWS Account Console Login Without MFA
slug: 2024-01-03-aws-single-factor-auth
description: Detection of successful AWS console login events without multi-factor authentication (MFA) enabled, potentially indicating misconfiguration, policy violation, or account compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloud
  - iam
  - authentication
  - account-takeover
vendors:
  - AWS
products:
  - AWS Identity and Access Management
  - AWS Management Console
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://attack.mitre.org/techniques/T1621/
  - https://attack.mitre.org/techniques/T1078/004/
  - https://aws.amazon.com/what-is/mfa/
rules:
  - title: AWS Console Login Without MFA
    description: Detects successful AWS console logins without MFA enabled based on CloudTrail logs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Console Login Errors
    description: Detects AWS console login failures which might indicate credential access attempts
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This brief focuses on detecting successful AWS console logins that bypass multi-factor authentication (MFA). The absence of MFA during console login attempts is flagged using AWS CloudTrail logs. This activity is a red flag because it can indicate a misconfiguration in AWS IAM settings, a violation of security policies, or an active account takeover attempt. An attacker who successfully breaches an AWS account without MFA can potentially escalate privileges, exfiltrate sensitive data, or manipulate cloud resources, leading to significant business disruption. The detection leverages the `aws:cloudtrail` sourcetype.

## Attack Chain

1.  Initial Access: An attacker gains initial access to an AWS account's username and password through credential harvesting (T1586.003) or other means.
2.  Login Attempt: The attacker attempts to log in to the AWS Management Console using the compromised credentials.
3.  MFA Bypass: If MFA is not enforced for the account, the attacker successfully logs in without providing a second factor.
4.  Privilege Escalation: The attacker attempts to escalate privileges within the AWS environment by exploiting misconfigured IAM roles or policies.
5.  Resource Access: The attacker accesses sensitive AWS resources, such as S3 buckets, EC2 instances, or databases.
6.  Data Exfiltration: The attacker exfiltrates sensitive data from compromised AWS resources to an external location.
7.  Resource Manipulation: The attacker modifies or deletes AWS resources, causing disruption or damage to the environment.

## Impact

A successful AWS account compromise due to the absence of MFA can have severe consequences. These include unauthorized access to sensitive data, potential data exfiltration, resource manipulation, and significant financial losses. The impact can extend to compliance violations, reputational damage, and disruption of critical business operations. The analytic story "AWS Identity and Access Management Account Takeover" highlights this threat.

## Recommendation

*   Enable and enforce MFA for all AWS IAM users to mitigate the risk of account compromise (reference: https://aws.amazon.com/what-is/mfa/).
*   Deploy the Sigma rule `AWS Console Login Without MFA` to detect successful console logins without MFA based on AWS CloudTrail logs.
*   Investigate any detected instances of successful single-factor authentication to determine the legitimacy of the login attempt.
*   Review and strengthen AWS IAM policies to minimize the potential for privilege escalation (related to T1078.004).

---
title: AWS IAM Policy Default Version Manipulation
slug: 2024-01-aws-setdefaultpolicyversion
description: An adversary may set a default policy version in AWS IAM to potentially escalate privileges, especially if previous policy versions granted broader permissions, leading to unauthorized access and data breaches.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - iam
  - privilege-escalation
  - defense-evasion
vendors:
  - AWS
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078.004
    technique_name: 'Valid Accounts: Cloud Accounts'
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://bishopfox.com/blog/privilege-escalation-in-aws
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/
rules:
  - title: Detect AWS IAM Policy Default Version Change
    description: Detects changes to the default version of an IAM policy, which could indicate privilege escalation attempts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1078.004
      - T1555
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS IAM Role Policy Attachment Modification
    description: Detects modifications to attached role policies in AWS IAM which can lead to privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This brief focuses on the potential misuse of the `SetDefaultPolicyVersion` API call within AWS Identity and Access Management (IAM). An attacker who has already gained initial access to an AWS account might attempt to manipulate IAM policies to elevate their privileges. By setting a default policy version, the attacker may revert to a previous, more permissive version of the policy, effectively granting themselves broader access than intended. The activity is detected via CloudTrail logs, specifically looking for the `SetDefaultPolicyVersion` event sourced from `iam.amazonaws.com`. Successful exploitation can lead to significant data breaches and unauthorized resource access within the AWS environment. This technique is relevant for all AWS environments and requires careful monitoring of IAM activities.

## Attack Chain

1.  The attacker gains initial access to an AWS account, possibly through compromised credentials or a vulnerability in an application with IAM roles.
2.  The attacker enumerates existing IAM policies to identify potential targets for manipulation.
3.  The attacker identifies policy versions with more permissive settings than the currently active version.
4.  The attacker calls the `SetDefaultPolicyVersion` API to revert to a previous policy version with the broader permissions. The event `SetDefaultPolicyVersion` is logged in CloudTrail.
5.  The attacker attempts to perform actions that were previously unauthorized but are now permitted due to the changed policy version.
6.  The attacker exploits the elevated privileges to access sensitive data stored in S3 buckets, databases, or other AWS resources.
7.  The attacker exfiltrates the stolen data to an external location.

## Impact

A successful attack can lead to unauthorized access to sensitive data, potentially impacting thousands or millions of users depending on the organization's data storage practices. Industries like finance, healthcare, and government are particularly at risk due to the sensitive nature of their data. The attacker can also use the elevated privileges to disrupt services, modify configurations, or deploy malicious infrastructure within the compromised AWS environment. The damage can range from data breaches and financial losses to reputational damage and compliance violations.

## Recommendation

*   Deploy the Sigma rule `Detect AWS IAM Policy Default Version Change` to your SIEM and tune for your environment to detect suspicious activity (logsource: `aws:cloudtrail`, eventName: `SetDefaultPolicyVersion`).
*   Investigate any instances of `SetDefaultPolicyVersion` where the user is not a designated IAM administrator.
*   Review the policy versions being set as default to ensure they adhere to the principle of least privilege.
*   Implement multi-factor authentication (MFA) for all IAM users to reduce the risk of credential compromise (T1078.004).
*   Enable and monitor AWS CloudTrail logs for IAM-related events to provide visibility into policy changes.

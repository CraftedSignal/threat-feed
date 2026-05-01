---
title: AWS IAM Customer Managed Policy Version Manipulation for Privilege Escalation
slug: 2024-01-aws-iam-policy-manipulation
description: Successful creation of new or setting default versions of customer-managed IAM policies can indicate privilege escalation attempts by attackers modifying policy permissions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - aws
  - iam
vendors:
  - Amazon
products:
  - Amazon Web Services
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_SetDefaultPolicyVersion.html
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
rules:
  - title: AWS IAM Customer Managed Policy Version Created or Default Version Set
    description: Detects successful IAM API calls that create a new customer managed policy version or set the default version for an existing customer managed policy.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Policy Modification by Unusual Source IP
    description: Detects IAM policy modification events originating from outside known corporate IP ranges.
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

This detection identifies potentially malicious activity related to AWS Identity and Access Management (IAM) policies. Specifically, it focuses on the creation of new versions of customer-managed policies (`CreatePolicyVersion`) and the modification of the default version (`SetDefaultPolicyVersion`). Attackers who have compromised IAM users or roles with sufficient permissions (iam:CreatePolicyVersion or iam:SetDefaultPolicyVersion) can use these actions to escalate their privileges within the AWS environment. By introducing a more permissive policy version and setting it as the default, attackers can gain unauthorized access to resources and perform actions that would otherwise be restricted. This activity is especially concerning when the modified policies are attached to highly privileged roles or users, such as those used for administrative tasks or break-glass scenarios.

## Attack Chain

1. An attacker compromises an IAM user or role with permissions to modify IAM policies (`iam:CreatePolicyVersion` or `iam:SetDefaultPolicyVersion`).
2. The attacker identifies a customer-managed policy attached to a high-privilege role or user.
3. The attacker crafts a new policy version with overly permissive rules, such as wildcard actions and resources.
4. The attacker uses the `CreatePolicyVersion` API call to upload the malicious policy version to the target policy.
5. Alternatively, the attacker uses the `SetDefaultPolicyVersion` API call to set a pre-existing, but less restrictive, policy version as the default.
6. The compromised IAM user or role assumes the high-privilege role targeted in step 2.
7. The attacker gains elevated privileges based on the modified IAM policy.
8. The attacker performs unauthorized actions within the AWS environment, such as accessing sensitive data, modifying infrastructure, or creating new resources.

## Impact

Successful exploitation can lead to significant privilege escalation, allowing attackers to gain control over critical AWS resources and data. The number of affected users and roles depends on the scope of the compromised policy and its attachments. The consequences can include data breaches, service disruptions, and financial losses. In environments where IAM policies are not closely monitored, attackers may be able to maintain their elevated access for extended periods, further compounding the damage.

## Recommendation

*   Deploy the Sigma rule "AWS IAM Customer Managed Policy Version Created or Default Version Set" to your SIEM to detect suspicious policy modifications. Tune the rule based on your organization's baseline activity.
*   Review `aws.cloudtrail.request_parameters` logs to identify the `policyArn` and `policyDocument` associated with the policy changes detected by the rule.
*   Implement strong IAM governance practices, including the principle of least privilege and regular reviews of policy permissions, to minimize the impact of policy manipulation.
*   Monitor CloudTrail logs for `AttachUserPolicy`, `AttachRolePolicy`, or `CreatePolicyVersion` spikes from the same principal as detected policy modifications.
*   Enable MFA for all IAM users, especially those with permissions to manage IAM policies.

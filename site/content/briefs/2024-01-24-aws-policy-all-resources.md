---
title: AWS Policy Created Allowing All Resources
slug: 2024-01-24-aws-policy-all-resources
description: An AWS IAM policy version was created that allows all actions on all resources, potentially leading to privilege escalation or unauthorized access.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - iam
  - policy
  - privilege-escalation
vendors:
  - AWS
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_create_policy_version_to_allow_all_resources.yml
rules:
  - title: AWS IAM Policy Created Allowing All Resources
    description: Detects the creation of an AWS IAM policy version that allows all actions on all resources.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Policy Updated to Allow All Resources
    description: Detects an update to an AWS IAM policy version that allows all actions on all resources.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This brief addresses the creation of an AWS IAM policy version that grants excessive permissions, specifically allowing all actions ("*") on all resources ("*"). While the provided data is limited to the detection file's existence in Splunk's security content repository, such a policy configuration significantly elevates the risk of unauthorized access, data breaches, and privilege escalation within an AWS environment. A malicious actor or compromised user could leverage these permissions to perform virtually any operation within the AWS account. The date of publishing the detection (2026-02-25) suggests this is a known security concern.

## Attack Chain

1. An attacker gains access to an AWS account through compromised credentials or by exploiting a vulnerability in an application with IAM permissions.
2. The attacker uses the AWS CLI or management console to create a new IAM policy or modify an existing one.
3. The attacker sets the "Action" field in the policy to "*" (all actions).
4. The attacker sets the "Resource" field in the policy to "*" (all resources).
5. The attacker creates a new version of the policy with these permissive settings using the `CreatePolicyVersion` API call.
6. The attacker attaches this policy to an IAM user, role, or group, effectively granting broad access.
7. The attacker leverages these permissions to perform reconnaissance, identify sensitive data, or escalate privileges.
8. The attacker exfiltrates data, modifies configurations, or launches further attacks within the AWS environment.

## Impact

The impact of creating an IAM policy allowing all resources can be severe. A successful attack could lead to full compromise of the AWS environment, including data exfiltration, service disruption, and financial loss. The absence of resource-based constraints means any entity with the policy can access and modify any AWS service. The scope of the impact depends on the resources available in the AWS account, but it could potentially affect all services and data stored within.

## Recommendation

*   Deploy the Sigma rule `AWS IAM Policy Created Allowing All Resources` to your SIEM and tune for your environment to detect the creation of overly permissive policies.
*   Review all existing IAM policies and roles for overly permissive configurations, specifically looking for policies with `Action: "*"` and `Resource: "*"`.
*   Implement the principle of least privilege when assigning IAM permissions, granting only the minimum necessary access required for each user or role.
*   Enable AWS CloudTrail to log all API calls, including `CreatePolicyVersion`, to provide an audit trail of IAM policy changes.

---
title: AWS IAM AdministratorAccess Policy Attached to Role
slug: 2024-06-07-aws-iam-administratoraccess-policy-attached-to-role
description: An adversary with compromised AWS credentials may escalate privileges or persist in the environment by attaching the AdministratorAccess AWS managed policy to an existing IAM role.
date: "2024-06-07T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - iam
  - privilege-escalation
  - persistence
vendors:
  - AWS
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html
  - https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
rules:
  - title: AWS IAM AdministratorAccess Policy Attached to Role
    description: Detects the attachment of the AdministratorAccess policy to an IAM role, which could indicate privilege escalation or persistence attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Role Trust Policy Updated with Wildcard Principal
    description: Detects updates to an IAM role's trust policy that include a wildcard (*) principal, potentially allowing unauthorized access.
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

An adversary with access to a compromised AWS account can escalate privileges or maintain persistence by attaching the `AdministratorAccess` AWS managed policy to an existing IAM role. This is achieved using the `AttachRolePolicy` API operation. This action grants the target role unrestricted privileges, potentially leading to unauthorized access to resources and data. The `AdministratorAccess` policy provides full access to all AWS services and resources, enabling the attacker to perform any action within the AWS environment. This activity is particularly concerning if the role is assumable by other accounts or services, broadening the scope of potential compromise.

## Attack Chain

1. An attacker gains initial access to an AWS account through compromised credentials (e.g., leaked access keys, stolen passwords, or exploited vulnerabilities).
2. The attacker identifies a target IAM role within the AWS environment.
3. The attacker calls the `AttachRolePolicy` API operation.
4. In the `AttachRolePolicy` request, the attacker specifies the target IAM role (`aws.cloudtrail.request_parameters.roleName`) and the `AdministratorAccess` policy ARN (`arn:aws:iam::aws:policy/AdministratorAccess`).
5. The IAM service attaches the `AdministratorAccess` policy to the target role, granting it full administrative privileges.
6. The attacker assumes the compromised IAM role, gaining elevated permissions.
7. The attacker uses the elevated privileges to access sensitive data, modify configurations, or deploy malicious resources.
8. The attacker establishes persistence by creating new IAM users or roles with administrative privileges or by modifying existing roles to allow for future unauthorized access.

## Impact

Attaching the `AdministratorAccess` policy to an IAM role can lead to complete compromise of the AWS environment. A successful attack could result in unauthorized access to sensitive data, modification or deletion of critical resources, and deployment of malicious infrastructure. The impact extends to any service or application that relies on the compromised AWS account, potentially affecting thousands of users and systems. The broad scope of the `AdministratorAccess` policy allows the attacker to perform virtually any action within the AWS environment, making it a critical security risk.

## Recommendation

*   Deploy the Sigma rule `AWS IAM AdministratorAccess Policy Attached to Role` to detect instances of the `AdministratorAccess` policy being attached to IAM roles (rule).
*   Investigate any identified instances of the `AttachRolePolicy` API operation with `AdministratorAccess` to determine if they are authorized (rule).
*   Review the trust policies of affected IAM roles to ensure that only authorized principals can assume them (rule).
*   Enforce least privilege policies by limiting which users or roles can attach or modify administrative policies (overview).
*   Implement AWS IAM Access Analyzer to identify and remediate unintended access to resources (overview).
*   Monitor CloudTrail logs for unusual IAM activity, such as unexpected calls to the `AttachRolePolicy` API operation from unfamiliar IP addresses or user agents (overview).

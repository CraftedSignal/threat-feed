---
title: AWS IAM Privilege Operations via Lambda Execution Role
slug: 2024-01-09-aws-lambda-iam-privilege-escalation
description: Detection of IAM API calls that create or empower IAM users and roles, attach policies, or configure instance profiles when the caller is an assumed role session associated with AWS Lambda, potentially indicating privilege escalation or persistence.
date: "2026-05-01T20:57:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - iam
  - lambda
  - privilege-escalation
  - persistence
vendors:
  - Amazon
products:
  - AWS IAM
  - AWS Lambda
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html
rules:
  - title: AWS IAM Sensitive Operations via Lambda Execution Role
    description: Detects successful IAM API calls that create or empower IAM users and roles, attach policies, or wire roles to instance profiles when the caller is an assumed role session associated with AWS Lambda.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1098
      - T1136.003
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Sensitive Operations via Lambda User Agent
    description: Detects successful IAM API calls that create or empower IAM users and roles, attach policies, or wire roles to instance profiles when the user agent indicates AWS Lambda.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
      - T1098
      - T1136.003
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat focuses on the abuse of AWS Lambda execution roles to perform sensitive IAM operations. Lambda functions, often running with over-permissioned roles, can be exploited by adversaries to escalate privileges and establish persistence within an AWS environment. An attacker gaining control of a Lambda function can leverage its execution role to make IAM API calls that would normally require elevated permissions. This includes creating new IAM users or roles, attaching policies to existing IAM entities, and modifying EC2 instance profiles. The scope of this threat includes any AWS environment utilizing Lambda functions with IAM permissions.

## Attack Chain

1.  An attacker gains unauthorized access to a Lambda function, either through code injection, vulnerable dependencies, or misconfiguration.
2.  The attacker leverages the Lambda function's execution role, which has excessive IAM permissions.
3.  The attacker executes IAM API calls, such as `CreateUser`, `CreateRole`, or `CreateAccessKey`, to create new IAM identities.
4.  The attacker uses `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy`, or `PutRolePolicy` to grant elevated permissions to the newly created or existing IAM identities.
5.  The attacker modifies instance profiles using `CreateInstanceProfile` and `AddRoleToInstanceProfile` to prepare EC2 instances for lateral movement.
6.  The attacker uses the newly created or modified IAM identities to assume roles and access resources they were not previously authorized to access via `sts:AssumeRole`.
7.  The attacker achieves privilege escalation, gaining control over sensitive AWS resources and services.
8.  The attacker establishes persistence by creating rogue IAM users, roles, or access keys.

## Impact

A successful attack can lead to full compromise of the AWS environment. An attacker could create highly privileged IAM users and roles, granting them the ability to access and control all AWS resources. This can result in data breaches, service disruptions, and financial losses. The impact is magnified in environments where Lambda functions are heavily relied upon for critical business operations.

## Recommendation

*   Deploy the Sigma rule "AWS IAM Sensitive Operations via Lambda Execution Role" to your SIEM and tune for your environment to detect the described IAM API calls originating from Lambda execution roles.
*   Review and restrict the permissions granted to Lambda execution roles, following the principle of least privilege, to minimize the potential impact of a compromised function.
*   Monitor `aws.cloudtrail.user_identity.arn` to identify the Lambda function and associated deployment path responsible for the IAM API calls.
*   Investigate `aws.cloudtrail.request_parameters` for targets such as `userName`, `groupName`, `roleName`, `policyArn`, or `instanceProfileName` to understand the scope of the IAM operations.
*   Revoke or rotate the credentials of any compromised Lambda execution roles to prevent further unauthorized access.
*   Remediate any rogue IAM users, roles, or access keys created by the attacker to eliminate persistence mechanisms.

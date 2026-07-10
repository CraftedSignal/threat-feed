---
title: AWS IAM Privilege Escalation via AdministratorAccess Policy Attachment to Group
slug: 2024-01-aws-iam-privilege-escalation
description: An adversary with compromised AWS credentials may escalate privileges or establish persistence by attaching the AWS-managed AdministratorAccess policy to an IAM group using the AttachGroupPolicy API call, granting full administrative privileges across all AWS services to all group members.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
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
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachGroupPolicy.html
  - https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
rules:
  - title: AWS IAM AdministratorAccess Policy Attached to Group
    description: Detects when the AWS-managed AdministratorAccess policy is attached to an IAM group, potentially indicating privilege escalation or persistence attempts.
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
      - cloudtrail
  - title: AWS IAM Group Modification Events
    description: Detects potentially malicious modifications to IAM groups.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

This alert focuses on a privilege escalation and persistence technique in AWS environments. An attacker who has gained initial access with compromised credentials may attempt to broaden their access by attaching the AWS-managed `AdministratorAccess` policy to an existing IAM group. This is achieved through the `AttachGroupPolicy` API operation. The `AdministratorAccess` policy grants full administrative privileges across all AWS services. If successful, all members of the group inherit these privileges, potentially leading to widespread compromise of the AWS environment. This activity is detected through AWS CloudTrail logs, which record API calls made within the AWS environment. Defenders should monitor for unexpected attachments of the AdministratorAccess policy to IAM groups, especially if the calling identity is unusual or the group contains sensitive accounts.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the AWS environment through compromised IAM user credentials.
2.  **Discovery:** The attacker enumerates existing IAM groups using AWS CLI or API calls such as `ListGroups`.
3.  **Target Selection:** The attacker identifies a target IAM group to which they can attach the `AdministratorAccess` policy.
4.  **Privilege Check:** The attacker verifies they have the `iam:AttachGroupPolicy` permission for the target group.
5.  **Policy Attachment:** The attacker executes the `AttachGroupPolicy` API operation, specifying the ARN of the `AdministratorAccess` policy and the name of the target IAM group.
6.  **Verification:** The attacker verifies the policy attachment by using the `GetGroupPolicy` API operation or AWS CLI.
7.  **Privilege Exploitation:** The attacker, or other members of the compromised group, leverage the newly acquired administrative privileges to access sensitive data, modify configurations, or perform other malicious actions.
8.  **Persistence:** The attacker maintains persistent access by ensuring the `AdministratorAccess` policy remains attached to the group, even if their initial access method is revoked.

## Impact

Successful exploitation can result in complete compromise of the AWS environment. The attacker gains full control over all AWS services and resources. This includes the ability to access sensitive data stored in S3 buckets, modify EC2 instances, create or delete IAM users and roles, and disrupt critical services. The widespread nature of the `AdministratorAccess` policy means that a single successful attachment can lead to cascading failures and significant financial losses.

## Recommendation

*   Deploy the following Sigma rule to detect the attachment of the `AdministratorAccess` policy to IAM groups via CloudTrail logs.
*   Review IAM group memberships and associated policies regularly to enforce the principle of least privilege.
*   Use AWS IAM Access Analyzer to identify unintended access to AWS resources.
*   Implement Service Control Policies (SCPs) to restrict the attachment of highly permissive policies like `AdministratorAccess` at the organizational level.
*   Investigate any `AttachGroupPolicy` events where the user identity (`aws.cloudtrail.user_identity.arn`) is not expected to be performing this action.
*   Detach the `AdministratorAccess` policy from any affected groups (`aws iam detach-group-policy`) as a containment measure.

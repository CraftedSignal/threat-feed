---
title: AWS IAM User Added to Group with Elevated Privileges
slug: 2024-01-09-aws-iam-user-addition-to-group
description: An AWS IAM user was added to an IAM group which could lead to credential misuse, lateral movement, or privilege escalation if the group has elevated or admin privileges.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - iam
  - credential access
  - privilege escalation
vendors:
  - AWS
products:
  - IAM
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AddUserToGroup.html
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS IAM User Added to Group
    description: Detects when an IAM user is added to a group in AWS IAM.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS IAM Group Modified After Creation
    description: Detects a pattern where a group is created and then modified shortly after, potentially by an attacker preparing for user additions.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

The AWS Identity and Access Management (IAM) service controls access to AWS resources. Attackers can escalate privileges by adding a user to a group that has excessive permissions. This allows an attacker to quickly gain permissions for actions like credential misuse, lateral movement, or privilege escalation. This rule detects the addition of a user to a specified group in AWS IAM by monitoring the `AddUserToGroup` API call. This activity is often part of a larger attack chain involving initial access, privilege escalation, and persistence within the AWS environment. Defenders should monitor IAM group membership changes, especially when the target group carries elevated or admin privileges. The associated Elastic rule was last updated on 2026/04/10, but this brief analyzes the underlying technique.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or a misconfigured service.
2. The attacker enumerates existing IAM users and groups to identify potential targets for privilege escalation.
3. The attacker identifies a target IAM group with elevated permissions (e.g., `AdministratorAccess` or custom policies with broad permissions).
4. The attacker uses the `AddUserToGroup` API call to add a chosen IAM user to the identified privileged group. This is the event detected by this brief.
5. The added IAM user now inherits the permissions associated with the group.
6. The attacker leverages the newly acquired permissions to perform actions such as creating access keys, modifying security policies, or accessing sensitive data stored in S3 buckets or EC2 instances.
7. The attacker establishes persistence by creating new IAM users with admin privileges or by modifying existing roles and policies.
8. The attacker maintains access to the environment and exfiltrates data or causes disruption.

## Impact

If an attacker successfully adds a user to a privileged IAM group, they can gain control over AWS resources, potentially leading to data breaches, service disruptions, and financial losses. The addition of a user to a group with `AdministratorAccess` can grant the attacker full control over the AWS account, allowing them to modify any resource or access any data. Depending on the scope and sensitivity of the data, this could impact hundreds or thousands of users and customers.

## Recommendation

*   Deploy the Sigma rule provided below to detect the `AddUserToGroup` API call in your AWS CloudTrail logs and tune it for your environment.
*   Investigate any detected instances of `AddUserToGroup` to determine if the user was added legitimately and if the target group has appropriate permissions.
*   Review the privileges of existing IAM groups to ensure that they follow the principle of least privilege.
*   Implement multi-factor authentication (MFA) for all IAM users to prevent credential compromise and unauthorized access.
*   Monitor the `CreateGroup` and `AttachGroupPolicy` events as referenced in the overview, as these can precede the `AddUserToGroup` event.
*   Restrict the `iam:AddUserToGroup` permission to specific service principals with approval workflows as outlined in the overview.

---
title: AWS IAM Permissions Boundary Modification for Privilege Escalation
slug: 2026-07-aws-iam-permissions-boundary-modified
description: An adversary can achieve privilege escalation within an AWS environment by modifying or removing an existing IAM permissions boundary on an IAM user or role, thereby unlocking previously restricted permissions defined in attached identity policies.
date: "2026-07-03T15:53:59Z"
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
  - identity
  - threat-detection
vendors:
  - Amazon
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An adversary who can delete a boundary ('DeleteUserPermissionsBoundary', 'DeleteRolePermissionsBoundary') or replace it with a more permissive one ('PutUserPermissionsBoundary', 'PutRolePermissionsBoundary') can lift that cap and unlock permissions the identity's policies already grant, enabling privilege escalation.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/privilege_escalation_iam_permissions_boundary_modified.toml
rules:
  - title: AWS IAM Permissions Boundary Modified or Removed
    description: Detects the modification or removal of an IAM permissions boundary on an IAM user or role, which can be used for privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 1
---

This threat brief details a privilege escalation technique in AWS where an adversary manipulates IAM permissions boundaries. An IAM permissions boundary acts as a maximum permissions filter, limiting the effective permissions of an IAM identity (user or role), regardless of its attached identity policies. Adversaries who gain access to an AWS account with the ability to modify or remove these boundaries can elevate their privileges. By performing actions like `DeleteUserPermissionsBoundary`, `DeleteRolePermissionsBoundary`, `PutUserPermissionsBoundary`, or `PutRolePermissionsBoundary`, an attacker can lift this cap, allowing latent permissions already present in the identity's policies to become active. This technique is significant because it allows attackers to bypass intended security controls without directly attaching new policies, making it a critical concern for defenders to detect and prevent unauthorized boundary modifications.

## Attack Chain

1.  An attacker gains initial access to an AWS account and compromises an IAM principal (user or role) with permissions to modify IAM permissions boundaries (e.g., `iam:Put*PermissionsBoundary` or `iam:Delete*PermissionsBoundary`).
2.  The attacker identifies a target IAM user or role within the same AWS account whose effective permissions are constrained by an existing, more restrictive IAM permissions boundary.
3.  The attacker executes `DeleteUserPermissionsBoundary` or `DeleteRolePermissionsBoundary` to completely remove the existing permissions boundary from the target IAM principal.
4.  Alternatively, the attacker executes `PutUserPermissionsBoundary` or `PutRolePermissionsBoundary`, replacing the existing permissions boundary with a new one that is more permissive or effectively removes the restriction.
5.  Upon successful modification or removal, any permissions that were previously granted by the target principal's identity-based policies but blocked by the boundary immediately become effective.
6.  The attacker now leverages these newly unlocked permissions to perform unauthorized actions within the AWS environment, such as accessing sensitive data, modifying critical resources, or further extending their control.

## Impact

If this privilege escalation technique is successful, an attacker can gain control over AWS resources and data that were previously protected by the permissions boundary. This can lead to unauthorized data exfiltration, modification or destruction of critical infrastructure, disruption of services, or further compromise of the AWS environment. The specific impact depends on the latent permissions unlocked, which could range from read access to S3 buckets containing sensitive data to full administrative control over compute resources or critical applications. Organizations could face significant financial loss, reputational damage, and regulatory penalties.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM, which specifically detects AWS IAM Permissions Boundary modifications, and tune it for your environment to identify anomalous activity.
*   Restrict `iam:PutUserPermissionsBoundary`, `iam:PutRolePermissionsBoundary`, `iam:DeleteUserPermissionsBoundary`, and `iam:DeleteRolePermissionsBoundary` permissions to a very small set of highly trusted administrators and automated pipelines, as highlighted in the rule's description.
*   Enable comprehensive `aws.cloudtrail` logging and ensure events for `iam.amazonaws.com` are captured to monitor for the specific actions mentioned in the detection rule.
*   Investigate all alerts from the provided Sigma rule by examining `aws.cloudtrail.user_identity.arn` and `source.ip` to identify the principal performing the boundary change, and verify against approved change records.
*   Implement strong identity and access management practices, including least privilege for IAM users and roles, especially those with permissions to modify permissions boundaries.

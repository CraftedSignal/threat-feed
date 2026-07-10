---
title: AWS IAM Group Deletion Failure
slug: 2024-01-29-aws-iam-group-deletion-failure
description: Detection of a failed attempt to delete an AWS IAM group, which could indicate an attempt to remove audit trails or disrupt security policies.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - cloud
  - deletion
vendors:
  - AWS
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_iam_failure_group_deletion.yml
rules:
  - title: Detect Failed AWS IAM Group Deletion via CloudTrail
    description: Detects failed attempts to delete IAM groups based on AWS CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Failed AWS IAM Group Deletion with Specific Error
    description: Detects failed attempts to delete IAM groups when a specific error, like 'EntityNotDeletable', is encountered in CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert detects a failed attempt to delete an AWS Identity and Access Management (IAM) group. While not inherently malicious, repeated or unusual failures in deleting IAM groups can indicate a potential security incident. An attacker might attempt to delete groups to remove permission boundaries, disrupt access control, or evade detection by deleting audit trails associated with the group. This activity is relevant for organizations heavily reliant on AWS IAM for access management and control. Defenders should investigate the reason for the failure and the identity attempting the deletion.

## Attack Chain

1. **Initial Access:** An attacker gains access to an AWS account, potentially through compromised credentials or a misconfigured IAM role.
2. **Privilege Escalation (Attempt):** The attacker attempts to escalate privileges to gain the necessary permissions to delete IAM groups. This could involve exploiting existing roles or policies.
3. **Reconnaissance:** The attacker enumerates existing IAM groups within the AWS account to identify potential targets for deletion.
4. **IAM Group Deletion Attempt:** The attacker attempts to delete a specific IAM group using the AWS CLI, API calls, or the AWS Management Console.
5. **Deletion Failure:** The deletion attempt fails due to insufficient permissions, resource dependencies, or other IAM constraints.
6. **Retry or Lateral Movement:** The attacker may retry the deletion with different credentials or attempt to move laterally within the AWS environment to gain the necessary permissions.
7. **Persistence (Alternative):** If group deletion fails, attacker may attempt to modify group policies to weaken security posture
8. **Impact (Potential):** Successful group deletion would alter permissions structure of the AWS environment.

## Impact

A failed IAM group deletion, while not directly causing immediate damage, can signify ongoing malicious activity. If successful, deleting IAM groups can lead to unauthorized access to resources, disruption of services, and potential data breaches. The number of affected users and the severity of the impact depend on the privileges associated with the deleted groups. Targeted sectors include any organization leveraging AWS IAM for identity and access management. A successful attack could lead to significant financial losses and reputational damage.

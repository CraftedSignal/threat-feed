---
title: AWS IAM Policy Deletion Detection
slug: 2024-01-aws-iam-policy-deletion
description: Detection of AWS IAM policy deletion events, which could indicate malicious activity by a compromised account or insider threat.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - policy
  - cloudtrail
vendors:
  - AWS
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_iam_delete_policy.yml
rules:
  - title: Detect AWS IAM Policy Deletion
    description: Detects the deletion of IAM policies within an AWS environment by monitoring CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS IAM Policy Deletion by Unusual User Agent
    description: Detects IAM policy deletion events triggered by unusual user agents, potentially indicating compromised credentials.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This brief focuses on the detection of AWS Identity and Access Management (IAM) policy deletion events. While legitimate IAM policy changes are common, the unauthorized or malicious deletion of policies can disrupt cloud infrastructure, leading to denial of service or privilege escalation. The detection focuses on activity within AWS environments and aims to identify potentially malicious actors removing IAM policies. This alert helps security teams quickly identify and respond to potentially malicious modifications of cloud infrastructure.

## Attack Chain

1.  Attacker gains initial access to an AWS account, possibly through compromised credentials or a vulnerability.
2.  The attacker enumerates existing IAM policies to understand the permission structure.
3.  Attacker identifies a target IAM policy to disable or delete.
4.  The attacker uses AWS CLI or API calls to initiate the deletion of the IAM policy.
5.  AWS CloudTrail logs record the `DeletePolicy` event with details about the actor, policy ARN, and timestamp.
6.  The policy is removed from the AWS environment.
7.  Services or users relying on the deleted policy lose permissions, potentially causing disruption.
8.  Attacker attempts to cover tracks by deleting relevant CloudTrail logs (requires elevated privileges).

## Impact

Successful deletion of IAM policies can lead to significant disruption of AWS environments. Services and users that depend on the deleted policy will lose the associated permissions, potentially causing denial of service or privilege escalation scenarios. This could affect critical applications, data access, and overall infrastructure stability. The scope of the impact depends on the importance and breadth of the deleted policy, potentially affecting entire departments or organizations.

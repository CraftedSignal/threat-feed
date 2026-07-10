---
title: AWS IAM Group Creation for Persistence
slug: 2024-01-aws-iam-group-creation
description: An adversary with compromised IAM write privileges creates a new group in AWS IAM and grants it excessive permissions to establish a persistence mechanism.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - iam
  - persistence
  - cloud
vendors:
  - AWS
products:
  - AWS Identity and Access Management (IAM)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/create-group.html
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html
  - https://attack.mitre.org/techniques/T1136/
  - https://attack.mitre.org/techniques/T1136/003/
rules:
  - title: AWS IAM Group Creation
    description: Detects the creation of a new IAM group in AWS, which could be a sign of malicious activity.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Group Policy Attachment After Creation
    description: Detects the attachment of a policy to an IAM group shortly after its creation, potentially indicating malicious privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on the malicious creation of AWS IAM groups as a persistence mechanism. An attacker who has gained unauthorized access to an AWS account, specifically with IAM write privileges, might create a new IAM group. This new group is then configured with highly permissive policies, such as AdministratorAccess, or policies allowing broad access to resources such as S3 buckets or other IAM resources.  The adversary can then add users or roles to this newly created group, granting them the inherited, elevated privileges.  This activity is logged as a `CreateGroup` event within AWS CloudTrail. This technique allows the attacker to quietly maintain access to the AWS environment, even if the initially compromised credentials are revoked. The Elastic detection rule "AWS IAM Group Creation," last updated on April 10, 2026, aims to identify this activity.

## Attack Chain

1.  Initial compromise of AWS credentials with IAM write privileges (e.g., via phishing, credential stuffing).
2.  The attacker authenticates to the AWS environment using the compromised credentials.
3.  The attacker executes the `CreateGroup` API call via the AWS CLI or AWS Management Console to create a new IAM group.
4.  The attacker uses the `AttachGroupPolicy` API call to attach a highly permissive policy (e.g., AdministratorAccess) to the newly created IAM group.
5.  The attacker uses the `AddUserToGroup` API call to add existing IAM users or roles to the newly created IAM group, granting them elevated privileges.
6.  The attacker uses the newly gained privileges to access resources, modify configurations, or exfiltrate data.
7.  The attacker maintains persistent access by utilizing the added users/roles even if initial credentials are revoked.

## Impact

A successful attack can lead to a significant breach of confidentiality, integrity, and availability. An attacker with persistent, high-privilege access can modify critical infrastructure, steal sensitive data, or disrupt services. While the number of direct victims isn't specified in this source, the impact can range from a single compromised AWS account to widespread disruption across multiple organizations relying on the compromised AWS services. The severity depends on the level of access granted to the malicious group and the value of the resources accessible through that group.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect anomalous IAM group creation events.
*   Investigate any `CreateGroup` events, especially when followed by `AttachGroupPolicy` or `AddUserToGroup` events within a short timeframe (see "AWS IAM Group Creation" rule and investigation guide).
*   Monitor CloudTrail logs for `CreateGroup` events and correlate them with other IAM activity to identify suspicious patterns (refer to the `aws.cloudtrail.user_identity.arn` and related fields described in the provided documentation).
*   Implement the principle of least privilege, restricting who can call `iam:CreateGroup`, `iam:AttachGroupPolicy`, and `iam:AddUserToGroup` (as mentioned in the remediation steps).

---
title: AWS IAM Policy Version Created Allowing Access to All Resources
slug: 2024-01-aws-policy-all-resources
description: An AWS IAM policy version allowing access to all resources has been created, potentially leading to privilege escalation and unauthorized actions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - iam
  - privilege-escalation
  - cloudtrail
vendors:
  - Amazon Web Services
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://bishopfox.com/blog/privilege-escalation-in-aws
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/
rules:
  - title: AWS IAM Policy Allows All Actions on All Resources
    description: Detects the creation of an AWS IAM policy version that allows all actions on all resources.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CreatePolicy to allow all resources
    description: Detects the creation of a new AWS IAM policy that allows access to all resources by analyzing AWS CloudTrail logs.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert identifies the creation of a new AWS IAM policy version that grants broad permissions to all resources. The detection focuses on AWS CloudTrail logs and specifically looks for `CreatePolicyVersion` events where the associated policy document includes statements that allow all actions (`"Action": "*"`) on all resources (`"Resource": "*"`) within an AWS environment. This activity is concerning because it violates the principle of least privilege, significantly increasing the risk of unauthorized access and abuse. While AWS admins might create such policies legitimately, it is strongly advised against, and the activity must be verified.

## Attack Chain

1. An attacker compromises an AWS account or obtains valid credentials.
2. The attacker authenticates to the AWS Management Console or uses the AWS CLI with the compromised credentials.
3. The attacker uses the `CreatePolicyVersion` API call to create a new version of an existing IAM policy.
4. The policy document included in the `CreatePolicyVersion` API call specifies `Action: "*"` and `Resource: "*"` effectively granting all permissions on all resources.
5. The attacker attaches the modified IAM policy to a user, group, or role.
6. The user, group, or role now has excessive permissions, allowing them to perform actions they were not previously authorized to do.
7. The attacker leverages these elevated privileges to perform unauthorized actions, such as accessing sensitive data, modifying critical infrastructure, or launching new resources.
8. The attacker may further escalate privileges or move laterally within the AWS environment, compromising additional resources.

## Impact

Successful exploitation allows an attacker to gain extensive access to AWS resources, leading to unauthorized actions, data exfiltration, or further compromise of the AWS environment. The principle of least privilege is violated, potentially exposing the environment to misuse or abuse. The scope of the impact depends on the level of access granted by the overly permissive policy. It could lead to complete compromise of the AWS environment.

## Recommendation

*   Deploy the Sigma rule `AWS IAM Policy Allows All Actions on All Resources` to detect the creation of overly permissive IAM policies based on CloudTrail logs.
*   Review all instances flagged by the Sigma rule and verify the legitimacy of the policy changes.
*   Implement IAM Access Analyzer to identify existing IAM policies that grant overly broad access (reference: AWS documentation).
*   Enforce the principle of least privilege by granting only the permissions required to perform specific tasks (reference: AWS documentation).

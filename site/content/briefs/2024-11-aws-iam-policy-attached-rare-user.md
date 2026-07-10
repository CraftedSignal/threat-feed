---
title: AWS IAM Customer-Managed Policy Attached to Role by Rare User
slug: 2024-11-aws-iam-policy-attached-rare-user
description: Detects when an AWS Identity and Access Management (IAM) customer-managed policy is attached to a role by an unusual or unauthorized user, potentially indicating privilege escalation within the AWS environment.
date: "2024-11-04T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - iam
  - privilege-escalation
vendors:
  - AWS
products:
  - IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html
rules:
  - title: AWS IAM AttachRolePolicy by Uncommon User
    description: Detects when an AWS IAM customer-managed policy is attached to a role by a user that has not been seen doing this before.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Role Policy Attachment from Suspicious Source IP
    description: Detects when a customer managed IAM policy is attached to a role from an unusual source IP address.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies instances where an AWS IAM customer-managed policy is attached to a role by a user account that has not previously performed this action. Customer-managed policies allow granular permission control within an AWS account. An attacker gaining unauthorized access may attempt to attach policies to roles to escalate their privileges and gain broader access to resources. This activity is detected by monitoring CloudTrail logs for the `AttachRolePolicy` event, specifically focusing on combinations of cloud account ID, user name, and the target role ID that are rarely observed. This detection uses a "new terms" rule to identify unusual actor-role associations and requires at least version 9.2.0 of the Elastic Stack. This rule aims to identify potentially malicious actions by detecting anomalous IAM policy attachment activities, allowing security teams to investigate and remediate potential privilege escalation attempts.

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials or an exposed API key.
2.  The attacker enumerates existing IAM roles to identify potential targets for privilege escalation.
3.  The attacker creates or identifies a customer-managed IAM policy containing elevated permissions, such as broad access to S3 buckets or EC2 instances.
4.  The attacker executes the `AttachRolePolicy` API call to attach the malicious customer-managed policy to the targeted IAM role. This action is recorded in AWS CloudTrail logs.
5.  The targeted IAM role now inherits the permissions defined in the attached policy.
6.  The attacker assumes the compromised IAM role or uses it to perform privileged actions, such as accessing sensitive data or launching unauthorized resources.
7.  The attacker leverages the escalated privileges to move laterally within the AWS environment, potentially compromising other resources or accounts.
8.  The attacker achieves their final objective, which could include data exfiltration, resource destruction, or establishing a persistent foothold in the AWS environment.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, compromised AWS resources, and significant financial or reputational damage. An attacker may be able to gain complete control over the AWS environment by escalating privileges to the administrator level. While the specific number of victims and affected sectors are not specified, the potential impact is widespread across any organization utilizing AWS for critical infrastructure and data storage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unusual IAM policy attachments based on the `cloud.account.id`, `user.name`, and `entity.target.id` fields.
*   Enable real-time alerts and monitoring on IAM policy modifications to detect similar actions promptly, as mentioned in the rule's documentation.
*   Review and restrict role modification permissions for critical IAM roles, following the recommendation in the rule's response and remediation guidance.
*   Regularly audit IAM policies and role permissions to ensure unauthorized changes are quickly identified and addressed, per the suggested remediation steps.
*   Investigate any alerts generated by the Sigma rule by examining the `aws.cloudtrail.request_parameters` field to identify the attached policy's ARN and permissions.
*   Correlate findings with other CloudTrail events as described in the investigation steps by reviewing `event.action` and `event.provider` to identify which AWS services were accessed.

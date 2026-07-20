---
title: AWS IAM Customer-Managed Policy Attached to Role by Rare User
slug: 2026-07-aws-iam-privesc-rare-user
description: A detection rule by Elastic identifies potential privilege escalation within AWS environments by flagging when an AWS Identity and Access Management (IAM) customer-managed policy is attached to a role by an unusual or unauthorized user, indicating an attempt by an adversary to expand permissions, gain elevated access, or maintain persistence.
date: "2026-07-20T13:11:52Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud-security
  - privilege-escalation
  - aws-cloudtrail
  - aws-iam
vendors:
  - AWS
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may attach policies to roles to expand permissions and elevate their privileges within the AWS environment.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Adversaries may attach policies to roles to expand permissions and elevate their privileges within the AWS environment.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries could attach policies to roles to expand permissions, thereby increasing their capabilities and achieving elevated access.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html
---

This brief details a detection strategy for identifying potential privilege escalation attempts within Amazon Web Services (AWS) environments. The detection focuses on the `AttachRolePolicy` event in AWS CloudTrail logs, specifically when a customer-managed IAM policy is attached to a role by a user or identity that has not historically performed such an action for that specific role. Customer-managed policies are critical security constructs that define permissions within an AWS account. Unauthorized or anomalous attachment of these policies to roles can significantly expand an attacker's capabilities, leading to elevated access, unauthorized resource manipulation, or establishment of persistence. This anomaly-based detection helps defenders identify unusual administrative actions that could signal a compromise, even if the action itself appears legitimate in isolation.

## Attack Chain

1. **Initial Compromise**: An adversary gains initial access to an AWS account, often through compromised credentials (e.g., via phishing, exposed access keys, or vulnerable applications).
2. **Discovery**: The adversary enumerates IAM users, roles, and existing policies to identify potential targets for privilege escalation. They look for roles with limited permissions or policies that, if attached, could grant significant control.
3. **Privilege Escalation - Policy Attachment**: The adversary, using their compromised credentials, attempts to attach a pre-existing customer-managed policy (or one they've created) to an IAM role. This policy is chosen to grant additional, more potent permissions than the compromised identity originally possessed. The `AttachRolePolicy` API call is made for this purpose.
4. **Verification**: The attacker verifies that the policy attachment was successful and that the role now possesses the desired elevated permissions.
5. **Post-Exploitation Activity**: With escalated privileges, the adversary can now perform actions such as data exfiltration, resource modification or deletion, creation of new users for persistence, or further lateral movement within the AWS environment.
6. **Persistence**: The expanded permissions on the role can be used to establish various forms of persistence, making it harder to evict the adversary from the compromised account.

## Impact

Successful exploitation of this technique by an unauthorized actor could lead to significant security breaches. Adversaries can gain unrestricted access to sensitive data stored in S3 buckets, control over EC2 instances, or even full administrative control over the AWS account by attaching policies with broad permissions (e.g., `s3:*`, `ec2:*`, `iam:*`). The impact can range from data theft and financial fraud to service disruption and complete compromise of cloud infrastructure. The detection aims to prevent these outcomes by flagging the suspicious policy attachment, allowing for early intervention before extensive damage occurs.

## Recommendation

* **Monitor AWS CloudTrail logs for `AttachRolePolicy` events**: Deploy the described detection logic to your SIEM, focusing on the `iam.amazonaws.com` provider and `AttachRolePolicy` action, to identify anomalous policy attachments.
* **Investigate `aws.cloudtrail.user_identity.arn` and `entity.target.id` for anomalous activity**: When an alert fires, immediately investigate the user who initiated the policy attachment and the role to which the policy was attached using `aws.cloudtrail.user_identity.arn` and `entity.target.id` from CloudTrail logs.
* **Review `aws.cloudtrail.request_parameters` for attached policy details**: Analyze the specific customer-managed policy attached to the role, inspecting its ARN and content for sensitive permissions.
* **Restrict `iam:AttachRolePolicy` permissions**: Implement strict access controls and apply the principle of least privilege to limit which users or roles can attach policies to critical IAM roles.
* **Conduct regular IAM policy audits**: Periodically review all IAM policies and role permissions within your AWS environment to ensure that unauthorized or overly permissive changes are identified and remediated.

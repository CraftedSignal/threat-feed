---
title: AWS IAM AdministratorAccess Policy Attached to User
slug: 2024-01-aws-iam-privilege-escalation
description: An adversary with compromised AWS credentials may attempt to escalate privileges or persist access by attaching the AdministratorAccess AWS managed policy to an existing IAM user via the AttachUserPolicy API, granting full access to all AWS services and resources.
date: "2024-01-29T10:00:00Z"
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
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html
  - https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
rules:
  - title: AWS IAM AdministratorAccess Policy Attached to User
    description: Detects when the AdministratorAccess policy is attached to an IAM user, potentially indicating privilege escalation or persistence attempts.
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
  - title: AWS IAM User Creating Access Key After Admin Policy Attachment
    description: Detects the creation of an access key by a user shortly after the AdministratorAccess policy was attached, indicating possible misuse.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

An attacker with access to compromised AWS credentials may attempt to escalate privileges or persist access by attaching the `AdministratorAccess` AWS managed policy to an existing IAM user. This is achieved through the `AttachUserPolicy` API operation. The `AdministratorAccess` policy is a highly permissive AWS-managed policy that grants full access to all AWS services and resources. This activity is significant because it effectively elevates the compromised user to full administrative privileges within the AWS environment, allowing the attacker to perform almost any action. The targeted AWS environment may be running various services and applications, making the impact broad and potentially severe. Defenders need to monitor for this behavior because it bypasses normal permission controls and can be used for malicious purposes, such as data exfiltration, resource hijacking, or further lateral movement.

## Attack Chain

1. Initial Access: The attacker gains access to AWS credentials through phishing, credential stuffing, or other means.
2. Credential Validation: The attacker validates the compromised credentials by attempting to access AWS resources.
3. Reconnaissance: The attacker enumerates existing IAM users to identify a target for privilege escalation.
4. Privilege Escalation: The attacker uses the `AttachUserPolicy` API operation to attach the `AdministratorAccess` policy to the target IAM user.
5. Elevated Access: The attacker leverages the elevated privileges to access sensitive data, modify configurations, or create new resources.
6. Persistence: The attacker creates new access keys or modifies IAM roles to maintain persistent access to the AWS environment.
7. Lateral Movement: The attacker uses the elevated privileges to access other AWS accounts or resources.
8. Impact: The attacker exfiltrates sensitive data, disrupts services, or causes financial damage.

## Impact

Successful exploitation allows an attacker to gain complete control over an AWS environment. This can lead to data breaches, service disruption, financial losses, and reputational damage. The number of potential victims is dependent on the scope of the AWS environment and the data it contains. The targeted sectors are broad, as AWS is used across various industries, including finance, healthcare, and government. If the attack succeeds, the attacker can perform any action within the AWS environment, including deleting resources, modifying configurations, and accessing sensitive data.

## Recommendation

*   Deploy the first Sigma rule to detect the attachment of the `AdministratorAccess` policy via the `AttachUserPolicy` API in CloudTrail logs.
*   Deploy the second Sigma rule to detect the creation of new access keys by users who have recently had the `AdministratorAccess` policy attached (log source: `aws.cloudtrail`, event.action: `CreateAccessKey`).
*   Implement IAM service control policies (SCPs) to prevent attachment of `AdministratorAccess` except for trusted roles (reference: AWS Documentation).
*   Monitor CloudTrail logs for `AttachUserPolicy` events and investigate any unexpected attachments of the `AdministratorAccess` policy (log source: `aws.cloudtrail`).

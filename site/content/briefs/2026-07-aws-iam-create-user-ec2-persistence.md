---
title: AWS IAM User Creation via Compromised EC2 Assumed Role
slug: 2026-07-aws-iam-create-user-ec2-persistence
description: Adversaries leverage a compromised AWS EC2 instance's assumed IAM role to create new, unauthorized IAM users, establishing persistence within the AWS environment by granting themselves persistent access even after the initial compromise is remediated.
date: "2026-07-15T14:16:53Z"
lastmod: "2026-07-15T14:26:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - persistence
  - identity-and-access-management
  - ec2
  - privilege-escalation
  - iam
vendors:
  - Amazon Web Services
products:
  - AWS Identity and Access Management (IAM)
  - Amazon EC2
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Adversaries might exploit such permissions to establish persistence by creating new IAM users under unauthorized conditions.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An adversary with access to a set of compromised credentials may attempt to persist or escalate privileges by attaching additional permissions to compromised user accounts. This rule looks for use of the IAM AttachUserPolicy API operation to attach the highly permissive AdministratorAccess AWS managed policy to an existing IAM user.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An adversary with access to a set of compromised credentials may attempt to persist or escalate privileges by attaching additional permissions to compromised user accounts. This rule looks for use of the IAM AttachUserPolicy API operation to attach the highly permissive AdministratorAccess AWS managed policy to an existing IAM user.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html
  - https://www.dionach.com/en-us/breaking-into-the-cloud-red-team-tactics-for-aws-compromise/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/privilege_escalation_iam_administratoraccess_policy_attached_to_user.toml
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html
  - https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/
iocs:
  - type: domain
    value: iam.amazonaws.com
ioc_counts:
  domain: 1
rules:
  - title: AWS IAM User Creation via Compromised EC2 Assumed Role
    description: Detects the creation of an AWS IAM user by an assumed role on an EC2 instance. This behavior often indicates a compromised EC2 instance being used to establish persistence by creating new, unauthorized IAM users.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1136
      - T1136.003
    data_sources:
      - cloud
      - aws.cloudtrail
  - title: Detect AWS IAM AdministratorAccess Policy Attached to User
    description: Detects an adversary attaching the highly permissive AWS-managed 'AdministratorAccess' policy to an existing IAM user, which grants full control over the AWS account and indicates privilege escalation or persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1098.003
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 2
updates:
  - at: "2026-07-15T14:26:40Z"
    level: L2
    summary: 'added detection rule: Detect AWS IAM AdministratorAccess Policy Attached to User'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/privilege_escalation_iam_administratoraccess_policy_attached_to_user.toml
---

This threat involves adversaries who have successfully compromised an AWS EC2 instance and are using its attached IAM role to establish persistence within the victim's AWS environment. By leveraging the temporary credentials of an assumed role on the EC2 instance, attackers can invoke the `iam:CreateUser` API to provision new, unauthorized IAM users. This technique allows them to maintain access and control even if the initial EC2 instance compromise is detected and remediated. The activity is detectable via AWS CloudTrail logs, specifically by observing `CreateUser` events where the initiating identity is an `AssumedRole` originating from an EC2 instance. This behavior is a critical indicator of post-compromise activity and can lead to broader unauthorized access, privilege escalation, and data exfiltration if not promptly addressed.

## Attack Chain

1. An adversary gains initial access to an AWS environment, often by exploiting a vulnerability in an application running on an EC2 instance, or through compromised credentials that allow access to an instance.
2. Upon compromising the EC2 instance, the adversary extracts or utilizes the temporary security credentials associated with an IAM role attached to that instance.
3. The adversary uses these temporary credentials to assume the EC2 instance's IAM role, thereby gaining the permissions assigned to that role within the AWS account.
4. Leveraging the assumed role's permissions, the adversary executes the `iam:CreateUser` API call to provision a new, unauthorized IAM user account within the AWS environment.
5. To enable direct programmatic access for the newly created IAM user, the adversary generates an access key and secret access key for this user using the `iam:CreateAccessKey` API.
6. The adversary then attaches specific IAM policies to the newly created user via `iam:AttachUserPolicy` or `iam:PutUserPolicy` APIs, granting the desired level of persistent access and privileges to various AWS resources.
7. With the new IAM user and its associated permissions, the adversary establishes persistent access to the AWS account, enabling continued operations even if the original EC2 instance compromise is mitigated or the temporary role credentials expire.

## Impact

Successful execution of this technique grants adversaries persistent, unauthorized access to an AWS account, circumventing initial access vectors. This can lead to significant data breaches, resource manipulation, and further privilege escalation, ultimately impacting the confidentiality, integrity, and availability of an organization's cloud resources. The creation of new IAM users provides a stealthy foothold that is difficult to remove without thorough investigation. If unchecked, the adversary could launch further attacks, disrupt services, exfiltrate sensitive data, or deploy malicious infrastructure, potentially incurring substantial financial, reputational, and operational damage.

## Recommendation

* Deploy the provided Sigma rule to your SIEM and tune for your environment to detect `CreateUser` actions originating from EC2 instance assumed roles.
* Regularly review `aws.cloudtrail` logs for `CreateUser` events, particularly examining the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.request_parameters` fields to identify any unauthorized IAM user creations.
* Restrict IAM role permissions on EC2 instances to only the minimum necessary (`least privilege`) to prevent assumed roles from having `iam:CreateUser` or similar high-privilege actions.
* Implement proactive monitoring and alerts for `CreateAccessKey` and `AttachUserPolicy` actions, especially when performed by newly created users or from unusual sources, as these often follow user creation.
* Refer to the AWS IAM documentation and best practices for securing roles and permissions to limit the scope of potential compromise.

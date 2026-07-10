---
title: AWS IAM User Creates Access Keys For Another User
slug: 2024-01-aws-iam-access-key-creation
description: An adversary with access to compromised AWS credentials may attempt to persist or escalate privileges by creating a new set of access keys for an existing IAM user, potentially leading to unauthorized access to resources and data.
date: "2024-01-23T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - iam
  - persistence
  - privilege-escalation
vendors:
  - Amazon Web Services
products:
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/#iamcreateaccesskey
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-persistence/aws-iam-persistence
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html
rules:
  - title: AWS IAM CreateAccessKey For Another User
    description: Detects when an IAM user creates access keys for another IAM user, which can indicate persistence or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS IAM CreateAccessKey from Unusual Source IP
    description: Detects CreateAccessKey API calls originating from outside expected corporate IP ranges.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.001
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

An adversary with compromised AWS credentials may attempt to persist or escalate privileges by creating new access keys for another IAM user. This activity is detected by monitoring AWS CloudTrail logs for the `CreateAccessKey` API call, where the calling user (identified by `aws.cloudtrail.user_identity.arn`) is different from the target user (`aws.cloudtrail.request_parameters.userName`). The rule focuses on identifying actions that deviate from normal administrative workflows, such as expected credential rotation or account provisioning systems. Successful exploitation allows an attacker to maintain access even if the original compromised credentials are changed and enables lateral movement within the AWS environment, potentially impacting data confidentiality and integrity. This activity aligns with MITRE ATT&CK techniques T1098 (Account Manipulation) and its sub-technique T1098.001 (Additional Cloud Credentials).

## Attack Chain

1.  Attacker gains initial access to an AWS account using compromised credentials (e.g., leaked access keys or credentials obtained through phishing).
2.  The attacker authenticates to the AWS environment using the compromised credentials, leveraging the AWS CLI or API.
3.  The attacker identifies a target IAM user for persistence or privilege escalation.
4.  The attacker invokes the `CreateAccessKey` API call, specifying the target IAM user's username in the `aws.cloudtrail.request_parameters.userName` field, while using the compromised credentials in the `aws.cloudtrail.user_identity.arn` to authenticate.
5.  AWS IAM service processes the `CreateAccessKey` request and generates a new access key ID and secret access key pair for the target user.
6.  The attacker retrieves the new access key ID (`aws.cloudtrail.response_elements.accessKey.accessKeyId`) and secret access key from the API response.
7.  The attacker uses the newly created access keys to authenticate as the target user and perform unauthorized actions, such as accessing S3 buckets or launching EC2 instances.
8.  The attacker maintains persistent access to the AWS environment, even if the original compromised credentials are rotated or revoked.

## Impact

Successful exploitation allows the attacker to maintain persistent access to the AWS environment. The attacker can then perform unauthorized actions as the target user, potentially leading to data breaches, resource hijacking, and service disruption. Depending on the privileges associated with the target IAM user, the attacker could escalate privileges, access sensitive data stored in S3 buckets, or launch malicious EC2 instances. The impact is highly dependent on the permissions assigned to the compromised IAM user, the level of access achieved, and the sensitivity of the data and resources involved.

## Recommendation

*   Deploy the following Sigma rules to your SIEM to detect suspicious IAM access key creation events. Tune the rules based on your environment and expected administrative activity.
*   Monitor AWS CloudTrail logs for `CreateAccessKey` API calls where the calling user differs from the target user (identified by `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.request_parameters.userName` respectively).
*   Implement least-privilege IAM policies to limit the ability of users to create access keys for other users.
*   Enforce multi-factor authentication (MFA) for all IAM users, especially those with administrative privileges.
*   Review and audit IAM policies regularly to ensure they adhere to the principle of least privilege.
*   Follow the guidance in the AWS IR Playbooks for Credential Compromise and IAM Misuse for incident response procedures.

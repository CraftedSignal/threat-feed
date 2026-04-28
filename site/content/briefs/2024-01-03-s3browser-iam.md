---
title: AWS IAM User or Access Key Creation via S3 Browser
slug: 2024-01-03-s3browser-iam
description: The use of S3 Browser to create IAM users or access keys in AWS environments indicates a potential privilege escalation, persistence, or initial access attempt by threat actors leveraging a known cloud administration tool.
date: "2024-01-03T14:30:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cloud
  - aws
  - iam
  - privilege-escalation
  - persistence
vendors:
  - Amazon
products:
  - AWS IAM
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_s3browser_user_or_accesskey_creation.yml
rules:
  - title: AWS IAM User Creation via S3 Browser
    description: Detects the creation of IAM users in AWS environments via the S3 Browser utility, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM Access Key Creation via S3 Browser
    description: Detects the creation of IAM access keys in AWS environments via the S3 Browser utility, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1136
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The S3 Browser utility, a Windows-based client for managing Amazon S3 storage and other cloud services, can be abused by threat actors to create new IAM users or access keys within compromised AWS environments. This activity, if unauthorized, can lead to privilege escalation, persistence, or even initial access, depending on the context of the compromise. The use of S3 Browser is identifiable via the userAgent string in AWS CloudTrail logs. While legitimate use of S3 Browser for administrative tasks exists, its unexpected appearance in user activity, particularly in sensitive accounts, should be investigated. This activity is particularly concerning because it can allow attackers to establish a foothold in the cloud environment and move laterally.

## Attack Chain

1. An attacker gains initial access to an AWS environment, potentially through compromised credentials or an exploited vulnerability.
2. The attacker installs and configures S3 Browser on a compromised host or uses an existing installation.
3. The attacker authenticates S3 Browser to the AWS environment using existing compromised credentials or an assumed role.
4. The attacker uses S3 Browser to execute the `CreateUser` API call within AWS IAM.
5. The attacker configures the new IAM user with elevated privileges, potentially granting administrator access.
6. Alternatively, the attacker uses S3 Browser to execute the `CreateAccessKey` API call for an existing IAM user.
7. The attacker uses the newly created access key to perform actions within the AWS environment.
8. The attacker leverages the new user or access key for persistence, lateral movement, and data exfiltration within the AWS environment.

## Impact

Successful exploitation and IAM creation can lead to complete compromise of the AWS environment. An attacker with escalated privileges can access sensitive data, modify configurations, disrupt services, and deploy malicious infrastructure. Depending on the permissions granted to the created user or access key, the attacker could potentially pivot to other AWS accounts or services, leading to widespread damage. This can result in significant financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Deploy the Sigma rule "AWS IAM S3Browser User or AccessKey Creation" to your SIEM and tune for your environment to detect anomalous IAM activity originating from S3 Browser.
*   Investigate any instances of `CreateUser` or `CreateAccessKey` events in AWS CloudTrail logs where the `userAgent` contains "S3 Browser".
*   Implement multi-factor authentication (MFA) for all IAM users to mitigate the risk of credential compromise.
*   Review and enforce the principle of least privilege for all IAM users and roles to limit the impact of compromised credentials.

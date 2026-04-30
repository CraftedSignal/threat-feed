---
title: S3 Browser Used to Create IAM Login Profiles
slug: 2024-01-02-s3browser-iam-loginprofile
description: The S3 Browser utility is being used to enumerate IAM users lacking login profiles and subsequently create them, potentially for reconnaissance, persistence, and privilege escalation within AWS environments.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloud
  - iam
  - s3browser
  - privilege-escalation
  - persistence
vendors:
  - Amazon
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_s3browser_loginprofile_creation.yml
rules:
  - title: AWS IAM S3Browser LoginProfile Creation
    description: Detects S3 Browser utility performing reconnaissance looking for existing IAM Users without a LoginProfile defined then (when found) creating a LoginProfile.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1059.009
      - T1078.004
    data_sources:
      - aws
      - cloudtrail
  - title: AWS IAM CreateLoginProfile Events
    description: Detects creation of IAM Login Profiles
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

The threat involves the use of the S3 Browser utility, a Windows application, to interact with Amazon Web Services (AWS) Identity and Access Management (IAM). Attackers are leveraging S3 Browser to perform reconnaissance, specifically targeting IAM users that do not have a login profile configured. Upon identifying such users, the attacker proceeds to create a login profile for them. This tactic may be indicative of an attempt to gain unauthorized access or maintain persistence within the AWS environment. The activity is detectable via AWS CloudTrail logs and was first publicly reported in May 2023 in connection with the threat actor GUIVIL.

## Attack Chain

1.  Attacker gains initial access to a system with AWS CLI tools installed or uses a compromised IAM user with sufficient permissions.
2.  The attacker configures S3 Browser with valid AWS credentials, enabling interaction with the AWS environment.
3.  S3 Browser initiates a `GetLoginProfile` API call in AWS CloudTrail, to enumerate IAM users and identify those without existing login profiles.
4.  S3 Browser, upon finding an IAM user without a login profile, initiates a `CreateLoginProfile` API call.
5.  The attacker sets a password for the newly created login profile, gaining console access to the targeted IAM user account.
6.  The attacker logs into the AWS console using the newly created credentials.
7.  The attacker leverages the IAM user's permissions to perform further reconnaissance, lateral movement, or data exfiltration within the AWS environment.
8.  The attacker establishes persistence by maintaining access through the created login profile, even if other access methods are revoked.

## Impact

Successful exploitation allows attackers to gain unauthorized console access to previously unprotected IAM user accounts. This can lead to privilege escalation, data breaches, and disruption of cloud services. The lack of multi-factor authentication on newly created login profiles increases the risk of account compromise. The impact can range from reconnaissance to full-scale control of the AWS environment, depending on the permissions associated with the compromised IAM users.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `GetLoginProfile` and `CreateLoginProfile` events originating from the S3 Browser user agent in AWS CloudTrail logs.
*   Investigate any instances of IAM LoginProfile creation originating from unusual user agents or IP addresses.
*   Implement multi-factor authentication (MFA) for all IAM users, including those with console access to mitigate the impact of compromised credentials.
*   Review IAM policies to ensure least privilege and restrict the ability to create or modify LoginProfiles to authorized personnel only.

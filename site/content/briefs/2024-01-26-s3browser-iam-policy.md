---
title: S3Browser IAM Policy Creation with Default Bucket Name
slug: 2024-01-26-s3browser-iam-policy
description: An AWS IAM policy is created by the S3Browser utility with the default S3 bucket name placeholder, potentially indicating unauthorized access or misconfiguration.
date: "2024-01-26T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - aws
  - iam
  - s3browser
  - s3
  - policy
  - cloudtrail
vendors:
  - Amazon
products:
  - AWS IAM
  - AWS S3
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078.004
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_s3browser_templated_s3_bucket_policy_creation.yml
rules:
  - title: AWS IAM S3Browser Templated S3 Bucket Policy Creation
    description: Detects S3 browser utility creating Inline IAM policy containing default S3 bucket name placeholder value of '<YOUR-BUCKET-NAME>'.
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
  - title: AWS IAM Policy Creation Without MFA
    description: Detects the creation of IAM policies without multi-factor authentication (MFA) which may indicate a compromised account.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

The S3Browser utility is being used to create Inline IAM policies within AWS. This activity is flagged as suspicious when the policy includes the default S3 bucket name placeholder value of `<YOUR-BUCKET-NAME>`. This could indicate that the user has not properly configured the policy or is unaware of the implications of using a generic placeholder, potentially granting unintended access to S3 resources. This behavior was observed being used by the threat actor Guivil. The use of S3Browser in this manner poses a risk of privilege escalation, persistence, and unauthorized access to sensitive data stored in S3 buckets.

## Attack Chain

1. An attacker gains initial access to an AWS account, possibly through compromised credentials or misconfigured IAM roles (T1078.004).
2. The attacker utilizes the S3Browser utility to interact with AWS S3 buckets.
3. The attacker attempts to create an Inline IAM policy using S3Browser.
4. The attacker fails to replace the default bucket name placeholder `<YOUR-BUCKET-NAME>` with a specific bucket ARN.
5. The attacker saves the IAM policy with the default bucket name placeholder, leading to a broad or unintended scope of permissions.
6. The poorly configured policy is applied to a user, role, or group.
7. The attacker potentially escalates privileges or gains unauthorized access to S3 resources.
8. The attacker persists in the environment with the newly created or modified IAM policy.

## Impact

Creation of an IAM policy with the default bucket name placeholder leaves S3 buckets open to potential unauthorized access. A successful attack could lead to data exfiltration, data modification, or denial of service. The scope of the impact depends on the specific permissions granted within the policy and the resources accessible through the affected IAM user, role, or group.

## Recommendation

*   Deploy the Sigma rule "AWS IAM S3Browser Templated S3 Bucket Policy Creation" to your SIEM and tune for your environment to detect this specific activity.
*   Investigate any instances where `PutUserPolicy` events are associated with the S3Browser user agent (logsource: aws/cloudtrail).
*   Review existing IAM policies for the presence of the default bucket name placeholder `arn:aws:s3:::<YOUR-BUCKET-NAME>/*` (logsource: aws/cloudtrail).

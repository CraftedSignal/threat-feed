---
title: AWS S3 Bucket Lifecycle Rule Abuse for Log Deletion
slug: 2024-01-aws-s3-lifecycle-deletion
description: Attackers may abuse the AWS S3 PutBucketLifecycle API to rapidly delete CloudTrail logs by setting short expiration periods on S3 buckets, hindering incident response and forensic investigations.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - defense-evasion
vendors:
  - Amazon
  - Splunk
products:
  - CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.cloudtrail-lifecycle-rule/
rules:
  - title: AWS S3 Bucket Lifecycle with Short Expiration
    description: Detects PutBucketLifecycle events with expiration periods less than 3 days, indicating potential log deletion attempts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1485.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Bucket Lifecycle Creation by Unusual User Agent
    description: Detects PutBucketLifecycle events from unusual user agents, which could indicate attacker activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1485.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

Attackers may attempt to evade detection by manipulating AWS S3 bucket lifecycle rules to accelerate the deletion of CloudTrail logs. By using the `PutBucketLifecycle` API to set a short expiration period (less than three days) on an S3 bucket containing CloudTrail logs, adversaries can effectively erase their activity history. This technique is particularly relevant as it directly impacts the ability of security teams to conduct thorough investigations and respond effectively to breaches. The tactic aims to impair forensic investigations by eliminating critical log data, thereby obscuring attacker actions.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a misconfigured IAM role.
2. The attacker identifies the S3 bucket(s) used to store CloudTrail logs.
3. The attacker uses the AWS CLI or API to call the `PutBucketLifecycle` API, configuring a new lifecycle rule.
4. The lifecycle rule is configured with an `Expiration` parameter, setting the `Days` value to a low number (e.g., 1 or 2 days).
5. The attacker executes malicious activities within the AWS environment, knowing the logs will be quickly deleted.
6. The S3 lifecycle policy automatically deletes the CloudTrail logs after the specified short expiration period.
7. Security analysts attempting to investigate the attacker's activities find that the relevant CloudTrail logs are missing or incomplete, hindering their investigation.

## Impact

Successful manipulation of S3 bucket lifecycle rules can severely impede incident response efforts. By rapidly deleting CloudTrail logs, attackers can cover their tracks, making it difficult to trace their actions and understand the scope of the breach. This can lead to prolonged dwell time, increased data exfiltration, and greater overall damage. The impact is significant because it directly targets the visibility security teams rely on for threat detection and response.

## Recommendation

*   Deploy the Sigma rule `AWS S3 Bucket Lifecycle with Short Expiration` to detect suspicious `PutBucketLifecycle` API calls with expiration periods under three days.
*   Enable CloudTrail logging on all AWS accounts and ensure logs are stored in secure S3 buckets, as required for the detection rules to function.
*   Review and audit existing S3 bucket lifecycle policies to identify any rules with unusually short expiration periods.
*   Implement multi-factor authentication (MFA) for all IAM users and roles to prevent unauthorized access and manipulation of S3 bucket lifecycle rules.
*   Use AWS IAM policies to restrict the ability of users and roles to modify S3 bucket lifecycle configurations, limiting the potential for abuse.

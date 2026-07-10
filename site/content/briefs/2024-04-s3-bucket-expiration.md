---
title: AWS S3 Bucket Expiration Lifecycle Configuration Added for Defense Evasion
slug: 2024-04-s3-bucket-expiration
description: An adversary may add an expiration lifecycle configuration to an Amazon S3 bucket to automatically delete logs, forensic evidence, or sensitive objects, detected via the PutBucketLifecycle or PutBucketLifecycleConfiguration APIs with Expiration parameters.
date: "2024-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - s3
  - defense_evasion
  - indicator_removal
vendors:
  - Amazon
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html
rules:
  - title: AWS S3 Bucket Expiration Lifecycle Configuration Added
    description: Detects the addition of an expiration lifecycle configuration to an Amazon S3 bucket.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Bucket Lifecycle Configuration Deletion
    description: Detects the deletion of an expiration lifecycle configuration from an Amazon S3 bucket.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

Attackers can abuse Amazon S3 lifecycle rules, which automatically delete or transition objects after a set period, to cover their tracks. By configuring auto-deletion of logs, forensic evidence, or sensitive objects, adversaries can hinder investigations and maintain operational secrecy. This activity is detected by monitoring the use of the `PutBucketLifecycle` or `PutBucketLifecycleConfiguration` APIs with Expiration parameters. While legitimate administrators may use these configurations for cost management or retention policies, malicious use indicates potential defense evasion, particularly when applied to buckets containing audit, CloudTrail, or application logs. The original rule was created on 2024/04/12 and updated on 2026/04/10 by Elastic.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account through compromised credentials or an exploited vulnerability.
2. The attacker identifies an S3 bucket containing valuable data, such as logs, audit trails, or forensic evidence.
3. The attacker uses the AWS CLI or SDK to execute the `PutBucketLifecycle` or `PutBucketLifecycleConfiguration` API, setting an expiration policy.
4. The expiration policy is configured with a short expiration period (e.g., 1 day) and applies to the entire bucket or specific prefixes (e.g., `/logs/`).
5. The attacker enables the lifecycle policy to automatically delete objects after the defined expiration period.
6. Objects within the S3 bucket are silently and automatically deleted according to the configured lifecycle policy.
7. Investigators attempting to analyze the attacker's actions find that critical data is missing due to the expiration policy.
8. The attacker successfully evades detection and hinders forensic analysis by removing evidence of their malicious activities.

## Impact

A successful attack can lead to the deletion of critical security logs, audit trails, and forensic evidence stored in Amazon S3 buckets. This can severely impede incident response efforts, making it difficult or impossible to determine the scope and impact of a security breach. Organizations relying on S3 for compliance purposes may also face regulatory penalties due to the loss of required audit data. The severity depends on the type of data lost and the organization's reliance on that data for security and operational purposes.

## Recommendation

*   Deploy the Sigma rule "AWS S3 Bucket Expiration Lifecycle Configuration Added" to detect the use of `PutBucketLifecycle` or `PutBucketLifecycleConfiguration` APIs with Expiration parameters in your AWS environment.
*   Implement AWS Config rules like `s3-bucket-lifecycle-configuration-check` to monitor lifecycle changes.
*   Restrict `s3:PutLifecycleConfiguration` IAM permissions to specific administrative roles to prevent unauthorized modifications.
*   Enable S3 Object Lock on log or evidence buckets to enforce immutability and prevent deletion, referencing the "S3 Object Lock" documentation.
*   Review CloudTrail logs for `DeleteObject`, `PutBucketPolicy`, `PutBucketAcl`, or `PutBucketLogging` events around the same time as the lifecycle configuration change, as these may indicate attempts to disable visibility.

---
title: AWS S3 Bucket Configuration Deletion
slug: 2024-01-aws-s3-config-deletion
description: Detection of Amazon S3 bucket configuration deletions, such as bucket policies or encryption settings, indicating potential defense evasion or impact attempts by adversaries who may delete logging or policy configurations to disrupt forensic visibility and inhibit recovery.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - s3
  - defense_evasion
  - impact
vendors:
  - AWS
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html
  - https://attack.mitre.org/techniques/T1070/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
  - https://attack.mitre.org/techniques/T1562/008/
  - https://attack.mitre.org/techniques/T1490/
  - https://attack.mitre.org/tactics/TA0005/
  - https://attack.mitre.org/tactics/TA0040/
rules:
  - title: AWS S3 Bucket Configuration Deletion
    description: Detects the deletion of critical Amazon S3 bucket configurations.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1562
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Bucket Policy Put
    description: Detects creation of a new S3 Bucket Policy
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on the deletion of critical Amazon S3 bucket configurations, a tactic used to evade defenses and potentially cause impact. The targeted configurations include bucket policies, lifecycle configurations, and encryption settings. Adversaries may delete these to disrupt forensic visibility, inhibit recovery efforts, or prepare for data exfiltration or destructive operations. The activity is detected via the AWS CloudTrail logs, specifically targeting the `DeleteBucketPolicy`, `DeleteBucketReplication`, `DeleteBucketCors`, `DeleteBucketEncryption`, and `DeleteBucketLifecycle` API calls. This activity is typically administrative but when performed by unauthorized users, it can represent adversarial attempts to remove security controls or conceal malicious activity. It is crucial for defenders to monitor these events and correlate them with related S3 or IAM activity.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account, potentially through compromised credentials or a misconfigured IAM role.
2. The attacker enumerates existing S3 buckets to identify targets of interest.
3. The attacker identifies critical bucket configurations, such as bucket policies, lifecycle rules, or encryption settings.
4. The attacker executes a `DeleteBucketPolicy` API call to remove the bucket's access policy, potentially opening it to public access or removing protective access restrictions.
5. Alternatively, the attacker uses `DeleteBucketLifecycle` to prevent object archival or automatic backups, hindering data retention.
6. The attacker may then use `DeleteBucketEncryption` to disable encryption, exposing data at rest.
7. Following the configuration changes, the attacker performs data exfiltration using `GetObject` or `CopyObject` to an external account, or destructive actions like `DeleteObject`.
8. The attacker attempts to cover their tracks by deleting CloudTrail logs or other audit trails (covered by separate detections).

## Impact

Successful deletion of S3 bucket configurations can have significant consequences. It can lead to data breaches due to exposed buckets, hinder incident response efforts by removing access to logs and backups, and disrupt business continuity by disabling lifecycle rules. The potential impact ranges from minor data exposure to complete data loss, depending on the sensitivity of the data stored in the affected buckets and the effectiveness of backup strategies. Organizations that store sensitive data or use S3 for critical business functions are at the highest risk.

## Recommendation

*   Deploy the Sigma rule "AWS S3 Bucket Configuration Deletion" to your SIEM and tune for your environment to detect malicious configuration changes (rule provided below).
*   Enable AWS Config rules such as `s3-bucket-policy-check`, `s3-bucket-lifecycle-configuration-check`, and `s3-bucket-logging-enabled` to monitor for unauthorized changes, as suggested in the investigation guide.
*   Implement least-privilege principles for IAM roles, specifically restricting permissions to delete S3 bucket configurations to authorized personnel only.
*   Monitor CloudTrail logs for `DeleteBucketPolicy`, `DeleteBucketReplication`, `DeleteBucketCors`, `DeleteBucketEncryption`, and `DeleteBucketLifecycle` events, correlating them with other S3 and IAM activity (reference the `event.action` field in the rule).
*   Review and audit existing S3 bucket configurations regularly to ensure they align with security best practices and organizational policies.

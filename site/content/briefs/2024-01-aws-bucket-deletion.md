---
title: AWS S3 Bucket Deletion Detected via CloudTrail
slug: 2024-01-aws-bucket-deletion
description: An AWS S3 bucket deletion event was detected via CloudTrail logs, potentially indicating data loss or unauthorized access attempts.
date: "2024-01-02T14:27:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - s3
  - data_loss
vendors:
  - Amazon
products:
  - S3
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/delete-bucket.html
rules:
  - title: AWS S3 Bucket Deleted
    description: Detects the deletion of an S3 bucket in AWS CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    data_sources:
      - aws
      - cloudtrail
  - title: AWS S3 Bucket Delete Attempt Failed
    description: Detects a failed attempt to delete an S3 bucket, potentially indicating reconnaissance or unauthorized access attempts.
    platform: sigma
    severity: low
    tactics:
      - stealth
    data_sources:
      - aws
      - cloudtrail
  - title: AWS S3 Bucket Policy Deletion followed by Bucket Deletion
    description: Detects the deletion of S3 bucket policy followed by bucket deletion within a short timeframe.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    data_sources:
      - aws
      - cloudtrail
rules_count: 3
---

The deletion of S3 buckets is a critical event to monitor in AWS environments. While legitimate administrative actions may involve bucket deletion, unauthorized or accidental removal of buckets can lead to significant data loss and business disruption. This brief focuses on detecting such events through AWS CloudTrail logs, which record API calls made within the AWS infrastructure. Monitoring for `DeleteBucket` events helps identify potential malicious activity or unintentional misconfigurations that could compromise data availability and integrity. This detection focuses on identifying DeleteBucket API calls, successful or otherwise, within CloudTrail logs to provide early warning of potential data compromise.

## Attack Chain

1.  An attacker gains unauthorized access to an AWS account through compromised credentials or a privilege escalation exploit.
2.  The attacker lists existing S3 buckets to identify potential targets using the `ListBuckets` API call.
3.  The attacker identifies a target S3 bucket containing sensitive data.
4.  The attacker attempts to delete the target S3 bucket by issuing a `DeleteBucket` API call using the AWS CLI or SDK.
5.  CloudTrail logs the `DeleteBucket` event, including the user identity, timestamp, and bucket name.
6.  If successful, the S3 bucket and its contents are permanently deleted.
7.  The attacker may attempt to remove CloudTrail logs to cover their tracks, using the `DeleteTrail` API call.

## Impact

The deletion of an S3 bucket results in the permanent loss of all data stored within that bucket. This can lead to service disruption, data breaches, and financial losses, especially if the bucket contained critical business data or backups. The impact can range from temporary inconvenience to complete business failure depending on the criticality of the data lost and the organization's backup and recovery capabilities. Without proper monitoring and alerting, an S3 bucket deletion can go unnoticed for extended periods, hindering incident response efforts and potentially exacerbating the damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect S3 bucket deletion events in CloudTrail logs.
*   Investigate any detected `DeleteBucket` events to verify their legitimacy and ensure they were authorized by appropriate personnel.
*   Implement multi-factor authentication (MFA) for all AWS accounts to prevent unauthorized access and reduce the risk of credential compromise.
*   Enforce strict IAM policies and regularly review user permissions to minimize the blast radius of compromised accounts.
*   Enable versioning on S3 buckets to allow for the recovery of accidentally deleted objects, mitigating the impact of data loss.
*   Implement data backup and disaster recovery plans to ensure business continuity in the event of a successful bucket deletion attack.

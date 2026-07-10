---
title: AWS S3 Bucket Replication for Data Exfiltration
slug: 2024-01-03-aws-bucket-replication-exfiltration
description: An attacker enables S3 bucket replication to exfiltrate data to an external AWS account by creating a bucket replication rule.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - s3
  - exfiltration
  - bucket-replication
vendors:
  - Amazon
products:
  - S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
references:
  - https://hackingthe.cloud/aws/exploitation/s3-bucket-replication-exfiltration/
rules:
  - title: Detect AWS S3 Bucket Replication Creation
    description: Detects the creation of S3 bucket replication rules, which can be used for data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
  - title: Detect S3 Bucket Replication to External Account
    description: Detects S3 bucket replication rules where the destination bucket belongs to a different AWS account.
    platform: sigma
    severity: critical
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic detects the creation of S3 bucket replication rules, which can be abused to exfiltrate data to an attacker-controlled AWS account. The attacker leverages the `PutBucketReplication` API call within AWS CloudTrail logs to set up replication from a target S3 bucket to a destination bucket, which may be outside of the organization's control. This technique can bypass traditional perimeter defenses since the data transfer occurs within the AWS infrastructure. The activity is significant because it can indicate unauthorized data replication, potentially leading to data breaches and compliance violations. Defenders should monitor these events closely, especially when the destination bucket is outside the organization's AWS account or in an unexpected region.

## Attack Chain

1.  The attacker gains access to an AWS account with sufficient privileges to modify S3 bucket replication settings.
2.  The attacker identifies a target S3 bucket containing sensitive data.
3.  The attacker creates an S3 bucket in an external AWS account under their control.
4.  The attacker uses the `PutBucketReplication` API call to create a replication rule for the target bucket. The rule specifies the attacker-controlled bucket as the destination.
5.  AWS begins replicating objects from the target bucket to the attacker-controlled bucket.
6.  The attacker monitors the destination bucket to ensure successful data replication.
7.  The attacker downloads the replicated data from their bucket.
8.  The attacker deletes the replication rule to cover their tracks, although CloudTrail logs will still record the event.

## Impact

Successful exploitation allows attackers to exfiltrate potentially terabytes of data from S3 buckets without triggering typical network-based data exfiltration alerts. This could lead to significant data breaches, affecting customer PII, financial records, or intellectual property. The number of affected users/records depends on the contents of the S3 bucket. This can lead to compliance violations such as GDPR, HIPAA, or PCI DSS.

## Recommendation

*   Enable AWS CloudTrail logging for all S3 buckets and monitor for `PutBucketReplication` events.
*   Deploy the Sigma rule `Detect AWS S3 Bucket Replication Creation` to your SIEM and tune for your environment.
*   Investigate any `PutBucketReplication` events where the destination bucket is outside of your organization's AWS accounts.
*   Review S3 bucket policies and IAM roles to ensure least privilege and restrict access to S3 replication settings.

---
title: AWS S3 Bucket Replicated to Another Account
slug: 2024-07-aws-s3-bucket-replication
description: Detection of S3 bucket replication configurations sending data to a different AWS account, potentially indicating unauthorized data exfiltration by adversaries abusing replication rules.
date: "2024-07-12T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - s3
  - exfiltration
  - cloudtrail
vendors:
  - Amazon
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-walkthrough-2.html/
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html/
rules:
  - title: AWS S3 Bucket Replicated to Another Account
    description: Detects creation or modification of S3 bucket replication configuration to an external AWS account.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
      - T1567
      - T1567.002
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Replication Role Creation
    description: Detects the creation of an IAM role that is used for S3 replication.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The rule identifies the creation or modification of an S3 bucket replication configuration that sends data to a bucket in a different AWS account, a technique adversaries with write access to an S3 bucket may abuse to silently exfiltrate data. Cross-account replication, while legitimate for backup and disaster recovery, can be exploited to covertly exfiltrate large data volumes to attacker-controlled accounts. The rule detects `PutBucketReplication` events where the configured destination account differs from the source bucket's account, which may indicate unauthorized cross-account data movement.

## Attack Chain

1.  Attacker gains initial access to an AWS account, possibly through compromised credentials or an insecure IAM role.
2.  The attacker obtains write access to an S3 bucket within the compromised account.
3.  The attacker uses the `PutBucketReplication` API call to configure replication from the compromised S3 bucket to a bucket in a different, attacker-controlled AWS account. The `aws.cloudtrail.request_parameters` will contain the destination `Account` ID.
4.  The attacker configures an IAM role with necessary permissions for S3 replication. The `aws.cloudtrail.request_parameters` logs this via `Role=` value.
5.  Data is written to the source S3 bucket, triggering the replication process.
6.  The S3 service automatically copies new objects and updates to the destination bucket in the attacker-controlled account.
7.  The attacker accesses the replicated data from the destination bucket, completing the exfiltration.

## Impact

Successful exploitation results in the unauthorized exfiltration of data from the compromised AWS account to an attacker-controlled AWS account. The impact depends on the sensitivity of the data stored in the S3 bucket. This could lead to data breaches, compliance violations, and reputational damage. The number of affected buckets and accounts can vary depending on the scope of the initial compromise and the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule "AWS S3 Bucket Replicated to Another Account" to your SIEM and tune for your environment to detect suspicious cross-account replication activity.
*   Inspect `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` in AWS CloudTrail logs to identify the actor initiating the replication changes.
*   Enforce AWS SCPs that restrict cross-account replication except for explicitly approved destinations as a preventive measure.

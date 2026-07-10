---
title: Detection of Public AWS S3 Bucket Creation via CLI
slug: 2024-01-03-aws-s3-public-bucket
description: An AWS user creates a publicly accessible S3 bucket by using the AWS CLI to set permissive ACLs, potentially leading to unauthorized data access and data breaches.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - s3
  - cloudtrail
  - misconfiguration
  - data-breach
vendors:
  - Amazon
products:
  - Amazon S3
  - AWS Command Line Interface
  - AWS Identity and Access Management
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1530
    technique_name: Data Destruction
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/detect_new_open_s3_buckets_over_aws_cli.yml
rules:
  - title: Detect Public AWS S3 Bucket Creation via CLI
    description: Detects the creation of public S3 buckets via the AWS CLI by monitoring CloudTrail logs for PutBucketAcl events with permissive ACLs.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Public AWS S3 Bucket Creation via CLI - Full Control
    description: Detects the creation of public S3 buckets via the AWS CLI where full control is granted to AllUsers.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This brief focuses on the detection of publicly accessible Amazon S3 buckets created via the AWS Command Line Interface (CLI). The creation of public S3 buckets is a common security misconfiguration that can lead to sensitive data exposure. This activity is detected by analyzing AWS CloudTrail logs for `PutBucketAcl` events where the bucket's access control list (ACL) is configured to grant read, write, or full control to "AuthenticatedUsers" or "AllUsers." This activity is particularly important to monitor because it represents a direct path for unauthorized access to data stored within the S3 bucket. The detection logic is based on the Splunk Security Content analytic "Detect New Open S3 Buckets over AWS CLI" (version 9, published April 15, 2026). Successfully exploited public buckets can lead to data exfiltration, data corruption, or other malicious activity.

## Attack Chain

1.  An attacker gains access to valid AWS credentials, potentially through compromised user accounts or leaked API keys.
2.  The attacker uses the AWS CLI to create a new S3 bucket using the `aws s3api create-bucket` command.
3.  The attacker then uses the `aws s3api put-bucket-acl` command to modify the bucket's Access Control List (ACL).
4.  In the `put-bucket-acl` command, the attacker sets permissions to grant read, write, or full control to "AuthenticatedUsers" or "AllUsers" by manipulating the `x-amz-grant-read`, `x-amz-grant-write`, and `x-amz-grant-full-control` parameters.
5.  AWS CloudTrail logs the `PutBucketAcl` event, capturing details of the user, bucket name, and ACL configuration.
6.  The attacker uploads sensitive data to the newly created, publicly accessible S3 bucket.
7.  Unauthorized users or automated bots discover the public S3 bucket and access the exposed data.
8.  The attacker exfiltrates the publicly available data, or modifies/corrupts data within the bucket.

## Impact

Creation of publicly accessible S3 buckets can lead to severe data breaches. Unauthorized access to sensitive data stored in these buckets can result in financial loss, reputational damage, and legal liabilities. The number of affected individuals or organizations can vary widely, depending on the type and amount of data exposed. Public buckets can be indexed by search engines, further increasing the risk of unauthorized access. Data exfiltration or corruption can severely disrupt business operations and erode customer trust.

## Recommendation

*   Deploy the Sigma rule "Detect Public AWS S3 Bucket Creation via CLI" to your SIEM and tune for your environment to detect the described activity based on CloudTrail logs.
*   Review and harden IAM policies to restrict the ability of users and roles to modify S3 bucket ACLs, preventing unintended public access.
*   Regularly audit existing S3 buckets to identify and remediate any publicly accessible buckets, using AWS Trusted Advisor or similar tools.
*   Implement automated monitoring and alerting for S3 bucket ACL changes using AWS CloudWatch Events and Lambda functions.
*   Enforce the principle of least privilege by granting only necessary permissions to users and roles, minimizing the risk of accidental or malicious misconfiguration.

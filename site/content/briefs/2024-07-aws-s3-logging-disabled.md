---
title: AWS S3 Bucket Server Access Logging Disabled
slug: 2024-07-aws-s3-logging-disabled
description: An adversary may disable server access logging for an Amazon S3 bucket in order to impair defenses by removing logs that contain evidence of malicious activity.
date: "2024-07-12T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - s3
  - defense-evasion
vendors:
  - AWS
products:
  - S3
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html
rules:
  - title: AWS S3 Bucket Server Access Logging Disabled
    description: Detects when server access logging is disabled for an Amazon S3 bucket.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Bucket Server Access Logging Disabled - EQL
    description: Detects when server access logging is disabled for an Amazon S3 bucket using EQL.
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

This detection identifies when server access logging is disabled for an Amazon S3 bucket. S3 server access logs provide a detailed record of requests made to a bucket, crucial for security monitoring and incident response. Disabling these logs impairs defenses by removing evidence of malicious activity, potentially indicating an adversary's attempt to hide their actions within the AWS environment. This activity is detected by analyzing AWS CloudTrail logs for `PutBucketLogging` events where the `LoggingEnabled` parameter is absent or explicitly disabled. The focus is on successful events that indicate a configuration change resulting in the cessation of logging, which is a key indicator of potential malicious intent to evade detection and forensic analysis. This event is particularly concerning if the affected bucket is used to store audit or access logs.

## Attack Chain

1.  The attacker gains initial access to the AWS environment, potentially through compromised credentials or a misconfigured IAM role.
2.  The attacker identifies an S3 bucket of interest, possibly containing sensitive data or logs.
3.  The attacker uses AWS CLI, API calls, or the AWS Management Console to execute the `PutBucketLogging` action against the target S3 bucket.
4.  The `PutBucketLogging` request is crafted without the `LoggingEnabled` parameter or with the parameter explicitly set to disable logging.
5.  The S3 service processes the request and successfully disables server access logging for the specified bucket.
6.  The AWS CloudTrail service records the `PutBucketLogging` event with an outcome of "success".
7.  The attacker may then perform actions such as `GetObject`, `CopyObject`, or `DeleteObject` on the S3 bucket without generating server access logs.
8.  The attacker attempts to cover their tracks by deleting CloudTrail logs or further modifying IAM policies.

## Impact

Disabling S3 server access logging significantly reduces the ability to monitor access to the S3 bucket, hindering incident response and forensic investigations. If the S3 bucket contains sensitive data, an attacker could exfiltrate or manipulate the data without detection. This could lead to data breaches, financial loss, and reputational damage. The impact is magnified if the bucket is used to store audit logs, as it impairs the ability to detect and investigate other security incidents.

## Recommendation

*   Deploy the Sigma rule `AWS S3 Bucket Server Access Logging Disabled` to your SIEM and tune for your environment to detect the disabling of S3 bucket logging.
*   Enable AWS Config rule `cloudtrail-s3-bucket-access-logging` to alert if logging is disabled, as recommended in the overview.
*   Apply bucket-policy or SCP restrictions to prevent unauthorized modifications of `PutBucketLogging` for audit/logging buckets, as mentioned in the overview.
*   Review AWS Config or Audit logs to see if the bucket’s logging was previously enabled and how long it has been disabled.
*   Monitor CloudTrail logs for preceding or subsequent events by the same principal or for the same bucket related to permissions changes, such as `PutBucketAcl`, `PutBucketPolicy`, or `RemoveBucketAccessPoint`.

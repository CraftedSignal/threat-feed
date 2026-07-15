---
title: AWS S3 Bucket Server Access Logging Disabled
slug: 2026-07-aws-s3-logging-disabled
description: Adversaries disable Amazon S3 server access logging by performing the PutBucketLogging API call without the LoggingEnabled parameter, aiming to impair defensive visibility and hide subsequent malicious activities such as data exfiltration or manipulation.
date: "2026-07-15T14:00:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - s3
  - defense-evasion
  - logging
vendors:
  - Amazon
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: When server access logging is disabled for a bucket, it could indicate an adversary's attempt to impair defenses by disabling logs that contain evidence of malicious activity.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html
rules:
  - title: AWS S3 Bucket Server Access Logging Disabled
    description: Detects when server access logging for an Amazon S3 bucket is disabled via the PutBucketLogging API call, indicating a potential defense evasion attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.008
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

This brief details the detection of server access logging being disabled for Amazon S3 buckets, a critical defense evasion technique employed by adversaries. When an attacker gains unauthorized access to an AWS environment, one of their first steps may be to remove evidence of their actions. By issuing a `PutBucketLogging` API call to an S3 bucket without specifying a `LoggingEnabled` configuration, they effectively disable the detailed record of requests to that bucket. This action impairs the organization's ability to track object access, identify data exfiltration, or detect data manipulation, significantly degrading forensic capabilities. This behavior is a strong indicator that an attacker is preparing to perform or has just performed malicious activities while minimizing audit evidence.

## Attack Chain

1. **Initial Access**: An attacker obtains unauthorized access to an AWS account or role with sufficient S3 permissions, typically through compromised credentials, API key exposure, or exploiting vulnerable services.
2. **Reconnaissance/Targeting**: The attacker identifies S3 buckets of interest, particularly those containing sensitive data, audit logs, or backups, that are candidates for data exfiltration or integrity compromise.
3. **Defense Evasion - Disable S3 Server Access Logging**: The attacker executes the `PutBucketLogging` API call, issuing a request that disables server access logging for one or more target S3 buckets. This is achieved by providing an empty `BucketLoggingStatus` configuration in the API call's parameters, thereby ensuring that `LoggingEnabled` is not specified.
4. **Perform Malicious Activity**: With server access logging disabled, the attacker proceeds to carry out their primary objective, such as exfiltrating sensitive data from the S3 bucket (e.g., via `GetObject` calls), deleting critical information (`DeleteObject`), or manipulating existing objects (`PutObject`), with significantly reduced audit trail visibility.
5. **Exfiltration/Impact**: Data is successfully exfiltrated or corrupted, and due to the disabled logging, identifying the specific actions and their timing becomes challenging.
6. **Maintain Persistence (Optional)**: The attacker may attempt to establish persistence within the compromised AWS environment to enable future access, while the impaired S3 logging continues to obscure their activities.

## Impact

Successful exploitation results in a severe degradation of forensic visibility for activities within affected S3 buckets. Organizations will struggle to track requests made to these buckets, making it difficult to detect data breaches, identify data manipulation, or reconstruct attacker actions. If the targeted buckets contain audit logs, access logs, or sensitive data, the impact is compounded, as critical evidence for incident response and compliance may be lost or rendered incomplete. This directly hinders an organization's ability to respond effectively to security incidents and maintain regulatory compliance.

## Recommendation

* Deploy the Sigma rule "AWS S3 Bucket Server Access Logging Disabled" to your SIEM to detect attempts to disable S3 server access logging.
* Ensure AWS CloudTrail logging is enabled across all AWS accounts to capture management events like `PutBucketLogging`.
* Immediately re-enable server-access logging for any affected S3 bucket where logging has been detected as disabled.
* Implement AWS Config rules (e.g., `cloudtrail-s3-bucket-access-logging`) to continuously monitor and alert on S3 bucket logging status changes.
* Restrict `s3:PutBucketLogging` permissions to only authorized roles and automate logging configuration via infrastructure-as-code where possible.

---
title: AWS S3 Object Versioning Suspended
slug: 2024-07-aws-s3-versioning-disabled
description: Detection of S3 bucket versioning suspension via PutBucketVersioning API call, potentially indicating an attempt to inhibit system recovery by making restoration of deleted or overwritten objects impossible.
date: "2024-07-12T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - s3
  - versioning
  - impact
vendors:
  - AWS
products:
  - S3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html/
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html/
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-s3-post-exploitation/
  - https://www.invictus-ir.com/news/ransomware-in-the-cloud/
  - https://rhinosecuritylabs.com/aws/s3-ransomware-part-2-prevention-and-defense/
rules:
  - title: AWS S3 Bucket Versioning Suspended
    description: Detects when S3 bucket versioning is suspended via PutBucketVersioning API call.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Bucket Versioning Suspended - EQL
    description: Detects when S3 bucket versioning is suspended via PutBucketVersioning API call using EQL.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when object versioning is suspended for an Amazon S3 bucket. Object versioning allows for multiple versions of an object to exist in the same bucket, enabling easy recovery of deleted or overwritten objects. Adversaries may disable object versioning to inhibit system recovery following malicious activity, such as data deletion or ransomware deployment. Versioning suspension can also facilitate bucket deletion. The rule leverages AWS CloudTrail logs and specifically looks for `PutBucketVersioning` API calls with a "Status=Suspended" parameter. This activity matters for defenders as it can signify a malicious actor attempting to reduce the recoverability of data within an AWS environment.

## Attack Chain

1. An adversary gains unauthorized access to an AWS account through compromised credentials or a misconfigured IAM role.
2. The adversary identifies an S3 bucket containing valuable data or backups.
3. The adversary executes a `PutBucketVersioning` API call to suspend versioning on the target S3 bucket. This can be done using the AWS CLI, SDK, or Management Console.
4. The `PutBucketVersioning` request includes the parameter `Status=Suspended`, which disables object versioning for the bucket.
5. The successful `PutBucketVersioning` call is logged in AWS CloudTrail.
6. The adversary proceeds to delete or overwrite objects within the S3 bucket.
7. Because versioning is suspended, the previous versions of the deleted or overwritten objects are not preserved, preventing easy recovery.
8. The adversary achieves their objective of hindering system recovery and potentially causing data loss or disruption.

## Impact

Suspending S3 object versioning can lead to significant data loss and hinder system recovery efforts. If an attacker suspends versioning and then deletes or overwrites objects, the organization may be unable to restore the data to its previous state. This can impact critical business operations, compliance requirements, and incident response capabilities. While specific numbers on victim counts are unavailable, the potential impact is high for organizations relying on S3 for data storage and backup.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `PutBucketVersioning` API calls with `Status=Suspended` in AWS CloudTrail logs.
*   Enable AWS Config rule `s3-bucket-versioning-enabled` to continuously monitor for versioning suspension and trigger automated alerts.
*   Restrict IAM permissions for `s3:PutBucketVersioning` to trusted administrators only to prevent unauthorized modifications.
*   Review CloudTrail logs for related actions such as `DeleteObject`, `PutBucketLifecycle`, or `PutBucketPolicy` by the same user or IP to determine whether versioning suspension preceded object deletion or policy manipulation.

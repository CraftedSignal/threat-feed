---
title: AWS S3 Bucket Versioning Disabled
slug: 2024-01-03-aws-disable-bucket-versioning
description: An adversary disables AWS S3 bucket versioning, preventing recovery of deleted or modified data as a potential precursor to data exfiltration or ransomware activity.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - s3
  - bucket_versioning
  - data_protection
  - ransomware
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
  - https://github.com/splunk/security_content/blob/main/detections/cloud/asl_aws_disable_bucket_versioning.yml
  - https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82
  - https://bleemb.medium.com/data-exfiltration-with-native-aws-s3-features-c94ae4d13436
rules:
  - title: Detect AWS S3 Bucket Versioning Suspension
    description: Detects when an AWS S3 bucket's versioning is suspended via the PutBucketVersioning API call.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - cloudtrail
      - aws
  - title: Detect ASL AWS S3 Bucket Versioning Disabled
    description: Detects when AWS S3 bucket versioning is suspended in Amazon Security Lake logs.
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

This detection identifies instances where an AWS user suspends versioning on an S3 bucket. The activity is logged via AWS CloudTrail and surfaced through Amazon Security Lake. This action is performed using the `PutBucketVersioning` API call and setting the `VersioningConfiguration.Status` to `Suspended`. While legitimate administrators may disable versioning for cost reasons, this activity can also be a precursor to malicious actions, such as data exfiltration or ransomware deployment by preventing recovery of previous object versions. Identifying this activity allows defenders to proactively respond to potential data compromise or data loss scenarios.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account, possibly through compromised credentials or exploiting an IAM role.
2. The attacker enumerates existing S3 buckets to identify potential targets for data exfiltration or disruption.
3. The attacker executes the `PutBucketVersioning` API call, setting the `VersioningConfiguration.Status` to `Suspended` for a target S3 bucket.
4. The S3 bucket no longer retains previous versions of objects. Any subsequent modification or deletion of objects is permanent.
5. The attacker uploads malicious files to the S3 bucket, or encrypts existing data rendering it unusable.
6. The attacker may then attempt to exfiltrate the data from the compromised S3 bucket.
7. The attacker covers their tracks by deleting CloudTrail logs, if possible.

## Impact

Disabling S3 bucket versioning can lead to significant data loss, especially in the event of accidental or malicious deletion or modification. This can impact business continuity and recovery efforts. If followed by ransomware activity, the organization may suffer data encryption, system downtime, and financial losses related to recovery and potential ransom payments. The number of affected buckets and the sensitivity of the data contained within them will determine the extent of the impact.

## Recommendation

*   Deploy the Sigma rule `Detect AWS S3 Bucket Versioning Suspension` to your SIEM and tune for your environment to detect suspicious disabling of bucket versioning.
*   Investigate any instances of disabled bucket versioning using the provided `drilldown_searches` to identify the user, source IP, and other related events.
*   Implement multi-factor authentication (MFA) for all AWS accounts and IAM roles to reduce the risk of unauthorized access.
*   Monitor CloudTrail logs for unusual API activity, particularly changes to S3 bucket configurations.
*   Enforce the principle of least privilege to limit the IAM permissions available to users and roles.
*   Review bucket access policies to ensure that only authorized users and services have access to sensitive data.

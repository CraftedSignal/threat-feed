---
title: AWS S3 Bucket Public Access Configuration
slug: 2024-01-new-open-s3-buckets
description: Detection of publicly accessible AWS S3 buckets created via PutBucketAcl operations, potentially leading to unauthorized data access, tampering, or exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - aws
  - s3
  - bucket
  - acl
  - public
  - misconfiguration
  - data-breach
vendors:
  - AWS
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1530
    technique_name: Data from Cloud Storage Object
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/detect_new_open_s3_buckets.yml
rules:
  - title: Detect New Open S3 Buckets via PutBucketAcl
    description: Detects the creation of open S3 buckets by monitoring PutBucketAcl events that grant access to AllUsers or AuthenticatedUsers.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect S3 Bucket ACL Modification to Public Access
    description: Detects modifications to existing S3 bucket ACLs to grant public access via PutBucketAcl.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief addresses the risk associated with misconfigured Amazon S3 buckets. Specifically, it focuses on the "PutBucketAcl" operation, which controls access permissions for S3 buckets. An adversary or insider with sufficient AWS privileges can configure an S3 bucket to be publicly accessible by granting read, write, or full control permissions to either "AllUsers" or "AuthenticatedUsers" AWS groups. This misconfiguration can lead to sensitive data exposure, unauthorized modification of bucket contents, or even complete compromise of the data stored within the S3 bucket. This activity is detected through analysis of AWS CloudTrail logs, providing a mechanism for identifying and remediating overly permissive S3 bucket configurations. This analytic became available on 2026-04-15.

## Attack Chain

1.  An attacker compromises an AWS account or uses a compromised IAM user with sufficient privileges (s3:PutBucketAcl).
2.  The attacker uses the AWS CLI, API, or console to create a new S3 bucket using a command such as `aws s3api create-bucket --bucket <bucket-name> --region <region>`.
3.  The attacker uses the AWS CLI, API, or console to modify the bucket's access control list (ACL) with `aws s3api put-bucket-acl --bucket <bucket-name> --acl public-read` or similar. This grants public access.
4.  The PutBucketAcl event is logged by AWS CloudTrail.
5.  If the bucket is exposed to full control, the attacker can modify the objects within.
6.  The attacker uploads malicious content (e.g., malware, phishing pages) to the S3 bucket.
7.  The attacker distributes links to the malicious content, leveraging the trust associated with AWS.
8.  The attacker exfiltrates sensitive data, modifies existing data, or uses the bucket as a staging ground for further attacks.

## Impact

A publicly accessible S3 bucket can have severe consequences. Sensitive data, including personally identifiable information (PII), financial records, or proprietary data, can be exposed to unauthorized individuals. This can lead to data breaches, compliance violations, reputational damage, and financial losses. Attackers can also modify or delete data, disrupting business operations or launching further attacks. The scale of impact depends on the sensitivity and volume of data stored in the compromised S3 bucket.

## Recommendation

*   Deploy the provided Sigma rule to detect `PutBucketAcl` events granting public access to S3 buckets based on the `cloudtrail` log source.
*   Investigate any detected instances of public S3 bucket creation or modification, focusing on the `user_arn` and `bucketName` to assess legitimacy.
*   Enforce the principle of least privilege by reviewing and tightening IAM policies to restrict the ability to modify S3 bucket ACLs using s3:PutBucketAcl to only authorized users and roles.
*   Implement automated checks using tools like AWS Config or AWS Trusted Advisor to continuously monitor S3 bucket permissions and identify publicly accessible buckets, remediating automatically where possible.

---
title: AWS User Performing S3 Encryption with KMS Keys
slug: 2024-01-aws-s3-encryption
description: A user with KMS keys is performing encryption operations on S3 buckets, potentially masking exfiltration or tampering efforts by encrypting sensitive data to evade detection or preparing it for exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - s3
  - encryption
  - ransomware
vendors:
  - AWS
products:
  - S3
  - KMS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
  - https://github.com/d1vious/git-wild-hunt
  - https://www.youtube.com/watch?v=PgzNib37g0M
rules:
  - title: AWS S3 Bucket Encryption with KMS Keys
    description: Detects S3 bucket encryption using KMS keys based on AWS CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Bucket Encryption by Uncommon User Agent
    description: Detects S3 bucket encryption using KMS keys by an unusual user agent.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic identifies instances of users employing KMS keys to encrypt objects within S3 buckets. The activity is detected by analyzing AWS CloudTrail logs for `CopyObject` events where server-side encryption with AWS KMS is specified, explicitly looking for `requestParameters.x-amz-server-side-encryption="aws:kms"`. This behavior is important because it might signify unauthorized or unusual data encryption, potentially concealing data exfiltration or tampering attempts. Attackers could use this to encrypt sensitive data to avoid detection or to prepare it for later exfiltration, thereby posing a considerable danger to the integrity and confidentiality of the data. The detection logic is sourced from Splunk's ES Content as of April 2026.

## Attack Chain

1. An attacker compromises an AWS account, either through stolen credentials or exploiting a misconfiguration.
2. The attacker uses the compromised AWS credentials to access the AWS environment.
3. The attacker identifies sensitive data stored within an S3 bucket.
4. The attacker uses the `CopyObject` operation in S3 to copy the object within the same bucket, or to another bucket.
5. During the `CopyObject` operation, the attacker specifies server-side encryption using AWS KMS (`requestParameters.x-amz-server-side-encryption="aws:kms"`).
6. The S3 bucket encrypts the copied object using the specified KMS key.
7. This action could be repeated across multiple objects and buckets.
8. The attacker may then exfiltrate the encrypted data, or leave it encrypted to disrupt operations.

## Impact

A successful attack could lead to the encryption of sensitive data within S3 buckets, potentially disrupting business operations and leading to data loss. The impact could range from a single bucket to multiple buckets across an entire AWS environment. The Rhino Security Labs reference details potential "S3 ransomware" scenarios that highlight the risk. Unauthorized encryption can be used to mask data exfiltration, making it more difficult to detect.

## Recommendation

*   Enable AWS CloudTrail logging and ensure logs are being ingested into your SIEM to detect the described behavior.
*   Deploy the Sigma rule "AWS S3 Bucket Encryption with KMS Keys" to detect the specific `CopyObject` event with KMS encryption.
*   Investigate any identified instances of users performing S3 encryption with KMS keys to determine if the activity is authorized.
*   Implement least privilege access controls to limit the ability of users to encrypt S3 objects with KMS keys.

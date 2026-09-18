---
title: Detecting S3 Ransomware via Cross-Account KMS Encryption
slug: 2026-09-s3-external-kms-encryption
description: Adversaries leverage S3 CopyObject API calls to encrypt data within victim buckets using external, attacker-controlled KMS keys, effectively denying access to the bucket owner.
date: "2026-09-18T19:35:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - s3
  - ransomware
  - impact
vendors:
  - Amazon
products:
  - S3
  - KMS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: This technique is a critical early signal of destructive intent or cross-account misuse.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html/
  - https://www.gem.security/post/cloud-ransomware-a-new-take-on-an-old-attack-pattern/
  - https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Enable S3 data event logging for CopyObject in CloudTrail
      owner: Cloud Security
      due: 48h
      evidence: Source metadata requirement for event capturing.
  hunt_leads:
    - lead: Search for CopyObject events where the KMS key account ID differs from the bucket account ID
      technique_id: T1486
      data_needed:
        - CloudTrail S3 data events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This behavior is unusual and a strong indicator of cloud ransomware techniques.
  mitigation_plan:
    - priority: immediate
      action: Enable S3 bucket versioning for critical buckets
      owner: IT Operations
      addresses: T1486
      evidence: Restore accessible previous versions if versioning is enabled.
---

This threat involves the exploitation of S3 bucket permissions where an adversary performs a `CopyObject` operation on objects in a target bucket while applying server-side encryption using an AWS KMS key located in a different AWS account. By forcing the encryption of these objects with an external key that the bucket owner cannot access, the attacker effectively renders the data unusable, mirroring traditional ransomware tactics within a cloud-native environment. This technique is often a precursor to further destructive activity or extortion. Defenders must differentiate these malicious events from legitimate cross-account data governance or migration workflows, which may involve centralized encryption accounts. The activity is particularly dangerous if object versioning is disabled, as the original unencrypted or differently encrypted data may be overwritten during the copy process.

## Attack Chain

1. Attacker performs reconnaissance to identify S3 buckets with overly permissive bucket policies or IAM roles with `s3:PutObject` permissions.
2. Attacker enumerates accessible objects using `ListObjectsV2` or `GetObject` calls.
3. Attacker gains access to an external AWS account and creates or identifies a target-ready KMS key.
4. Attacker executes the `CopyObject` API call targeting the victim bucket, specifying the external KMS key via the `x-amz-server-side-encryption-aws-kms-key-id` request parameter.
5. S3 processes the `CopyObject` request, re-encrypting the data with the attacker-controlled KMS key.
6. Victim bucket owner attempts to access the object but fails due to lack of decrypt permissions on the external KMS key.
7. Attacker potentially proceeds to delete original object versions (if versioning is enabled) or demands ransom for the KMS key access.

## Impact

The impact of this activity is the complete loss of data availability for the targeted S3 objects. If applied at scale, this technique can effectively neutralize entire buckets of data. If object versioning is disabled, the original data is overwritten and potentially unrecoverable, leading to significant operational disruption and data loss. This technique targets organizations using misconfigured cross-account IAM or S3 bucket policies.

## Recommendation

1. Enable S3 data event logging in AWS CloudTrail to capture `CopyObject` operations for all critical buckets.
2. Implement monitoring to alert on `CopyObject` events where the `kms_key_account_id` does not match the bucket owner's `cloud.account.id`.
3. Audit IAM roles and S3 bucket policies for overly permissive `s3:PutObject` access and ensure no unnecessary external accounts have write access.
4. Enforce AWS Service Control Policies (SCPs) that restrict KMS usage to explicitly approved AWS accounts.
5. Enable S3 bucket versioning to ensure that objects can be restored if they are overwritten by malicious `CopyObject` operations.

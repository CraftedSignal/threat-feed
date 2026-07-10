---
title: Unusual AWS S3 Object Encryption with SSE-C
slug: 2024-01-03-aws-s3-sse-c-encryption
description: Compromised AWS credentials are used to encrypt S3 objects using Server-Side Encryption with Customer-Provided Keys (SSE-C), rendering the objects unreadable without the attacker's key, potentially leading to data loss or extortion.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - s3
  - ransomware
  - data-encryption
vendors:
  - Amazon Web Services
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html
rules:
  - title: Detect S3 SSE-C Encryption
    description: Detects the use of Server-Side Encryption with Customer-Provided Keys (SSE-C) in AWS S3 PutObject events, which may indicate ransomware activity.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - cloudtrail
      - aws
  - title: Detect S3 SSE-C Encryption - First Time Use by User
    description: Detects the first time a user utilizes Server-Side Encryption with Customer-Provided Keys (SSE-C) in AWS S3 PutObject events within a 7 day window.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This rule identifies potentially malicious use of Server-Side Encryption with Customer-Provided Keys (SSE-C) within AWS S3. An attacker with compromised AWS credentials can use SSE-C to encrypt objects in an S3 bucket, effectively locking out legitimate users who do not possess the customer-provided key. This can be a ransomware tactic to extort the bucket owner or simply disrupt operations by making data inaccessible. The detection focuses on identifying first-time usage of SSE-C for a specific user and target bucket. The original rule was created on 2025/01/15, and updated on 2026/04/10.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account, potentially through credential stuffing, phishing, or exploiting vulnerabilities in EC2 instances.
2. The attacker enumerates S3 buckets accessible with the compromised credentials.
3. The attacker uses the `PutObject` API call to upload or modify an object within a target S3 bucket.
4. The attacker specifies the `x-amz-server-side-encryption-customer-algorithm` parameter within the `PutObject` request, setting its value to `AES256` to enable SSE-C.
5. The attacker also provides the `x-amz-server-side-encryption-customer-key` and `x-amz-server-side-encryption-customer-key-MD5` headers with the SSE-C encryption key and its MD5 hash, respectively.
6. The S3 service encrypts the object using the provided key. The legitimate owners are now unable to access the objects without the attacker's encryption key.
7. The attacker may upload a ransom note to the bucket, informing the victim of the encryption and demanding payment for the decryption key.
8. The attacker may delete the original, unencrypted objects after successfully encrypting them.

## Impact

A successful attack can lead to significant data unavailability, requiring restoration from backups or payment of a ransom to the attacker. The number of affected objects and buckets depends on the scope of the compromised credentials. Sectors handling sensitive data (e.g., healthcare, finance) are particularly vulnerable. The impact could range from operational disruption to severe financial losses and reputational damage.

## Recommendation

*   Enable AWS S3 data event logging in CloudTrail to monitor `PutObject` API calls (setup).
*   Deploy the Sigma rule "Detect S3 SSE-C Encryption" to identify potentially malicious encryption activity (rules). Tune the rule based on your environment's legitimate SSE-C usage.
*   Investigate any alerts triggered by the Sigma rule, focusing on identifying the user, source IP, and targeted bucket (rules).
*   Monitor for new or unusual IAM users or roles associated with S3 bucket access (references).
*   Review and tighten IAM policies to limit access to S3 buckets to only authorized users and roles (references).
*   Implement multi-factor authentication (MFA) for all AWS accounts to reduce the risk of credential compromise (references).

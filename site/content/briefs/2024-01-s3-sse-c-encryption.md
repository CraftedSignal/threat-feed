---
title: Excessive AWS S3 Object Encryption with SSE-C
slug: 2024-01-s3-sse-c-encryption
description: Compromised AWS credentials can be used to encrypt a large number of S3 objects with SSE-C, rendering them unreadable without the attacker's keys, potentially leading to a ransomware-like extortion scenario.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - s3
  - sse-c
  - ransomware
  - impact
vendors:
  - Amazon
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html
rules:
  - title: Detect AWS S3 Object Encryption with SSE-C
    description: Detects AWS S3 PutObject events where Server-Side Encryption with Customer-Provided Keys (SSE-C) is used.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of AWS S3 Object Encryption with SSE-C from Single IP
    description: Detects a high volume of S3 objects being encrypted with SSE-C from a single IP address within a short timeframe, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat involves the malicious use of Server-Side Encryption with Customer-Provided Keys (SSE-C) in AWS S3. Attackers, typically leveraging compromised AWS credentials, encrypt numerous objects within an S3 bucket using their own encryption keys. This action renders the objects unreadable and unrecoverable without the attacker's private keys. The primary motive behind this attack is extortion, where the bucket owner is coerced into paying for the decryption keys, effectively mirroring a ransomware attack in a cloud environment. The behavior is detected by monitoring for a high volume of PutObject events with SSE-C encryption within a short time window.

## Attack Chain

1. **Credential Compromise:** The attacker gains unauthorized access to AWS credentials through methods like phishing, credential stuffing, or exploiting vulnerable applications.
2. **Privilege Escalation (Optional):** If the compromised credentials have limited permissions, the attacker may attempt to escalate privileges to gain broader access within the AWS environment.
3. **Bucket Discovery:** The attacker uses the compromised credentials to enumerate available S3 buckets within the AWS account.
4. **Target Selection:** The attacker identifies a target S3 bucket containing sensitive or valuable data.
5. **SSE-C Encryption:** The attacker initiates a high volume of PutObject operations, encrypting the existing objects using SSE-C with attacker-controlled keys. The `x-amz-server-side-encryption-customer-algorithm` request parameter is set to "AES256".
6. **Data Denial:** The legitimate users are unable to access their data due to the encryption.
7. **Extortion:** The attacker demands payment for the decryption keys, holding the encrypted data hostage.

## Impact

A successful SSE-C encryption attack can lead to significant data loss and business disruption. The number of affected objects can range from hundreds to thousands, depending on the bucket size and attacker's dwell time. This can result in financial losses due to downtime, data recovery costs (if possible), and potential reputational damage. Industries heavily reliant on cloud storage, such as media, finance, and healthcare, are particularly vulnerable.

## Recommendation

*   Enable and monitor AWS CloudTrail logs, specifically for `PutObject` events with `x-amz-server-side-encryption-customer-algorithm: AES256`, to detect suspicious SSE-C encryption activity (see references and log source in the rules below).
*   Implement the provided Sigma rule to detect excessive S3 object encryption with SSE-C and tune the threshold for your environment.
*   Review and tighten IAM policies for roles and users accessing S3 buckets to enforce least privilege and prevent unauthorized encryption (see "setup" in source).
*   Disable or rotate any compromised access keys identified in the investigation process as documented in the "note" section of the source material.

---
title: Unusual AWS S3 Object Encryption with SSE-C
slug: 2026-07-aws-s3-unusual-encryption
description: Adversaries with compromised AWS credentials can exploit Server-Side Encryption with Customer-Provided Keys (SSE-C) in Amazon S3 to encrypt objects, rendering them unreadable and potentially enabling ransomware operations, which detection engineers can identify by monitoring CloudTrail logs for specific `PutObject` or `CopyObject` API calls.
date: "2026-07-14T09:07:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - s3
  - ransomware
  - encryption
  - impact
  - data-loss
vendors:
  - Amazon Web Services
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Adversaries with compromised AWS credentials can encrypt objects in an S3 bucket using their own encryption keys, rendering the objects unreadable or recoverable without the key. This can be used as a form of ransomware to extort the bucket owner for the decryption key.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries with compromised AWS credentials can encrypt objects in an S3 bucket using their own encryption keys.
    confidence_band: high
references:
  - https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html
rules:
  - title: Detect Unusual AWS S3 Object Encryption with SSE-C
    description: Detects when an S3 object is encrypted using Server-Side Encryption with Customer-Provided Keys (SSE-C), indicating potential ransomware activity. This rule flags `PutObject` or `CopyObject` API calls where the `x-amz-server-side-encryption-customer-algorithm` header is set to 'AES256', suggesting an attacker is re-encrypting data with their own key.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1078
      - T1078.004
      - T1486
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
---

This threat brief details how adversaries leverage compromised AWS credentials to perform ransomware activities by encrypting Amazon S3 objects using Server-Side Encryption with Customer-Provided Keys (SSE-C). This technique allows an attacker to use their own encryption keys for S3 objects, making the data inaccessible to the legitimate owner without the attacker's key, thereby facilitating extortion. This method represents a significant impact to data availability and integrity in cloud environments. The detection focuses on identifying the first-time use of SSE-C by a specific user on a target bucket, which is a strong indicator of malicious activity or a significant deviation from baseline behavior. This activity typically targets organizations storing critical data in S3 buckets, aiming to disrupt operations and extort payments.

## Attack Chain

1. **Initial Access**: Adversaries obtain valid AWS credentials, often through phishing, exposed access keys, or compromise of connected systems (e.g., EC2 instances, developer workstations).
2. **Credential Usage**: The adversary utilizes the compromised AWS credentials to authenticate to the AWS environment, gaining unauthorized access to the victim's cloud resources.
3. **Discovery**: The adversary identifies target S3 buckets and objects that hold valuable or critical data within the compromised AWS account, assessing their importance for potential impact.
4. **Object Modification**: The adversary initiates an S3 `PutObject` or `CopyObject` API call to modify existing objects or upload new ones within the targeted S3 bucket.
5. **Encryption Implementation**: During the `PutObject` or `CopyObject` operation, the adversary specifies the `x-amz-server-side-encryption-customer-algorithm: AES256` header in the request, providing their own customer-provided encryption key.
6. **Data Inaccessibility**: S3 objects are encrypted using the attacker's key, making them unreadable and inaccessible to the legitimate bucket owner without possessing that specific key.
7. **Data Withholding for Extortion**: The legitimate owner is locked out of their critical data, creating a situation ripe for extortion as attackers demand payment for the decryption key.
8. **Ransom Note Delivery (Optional)**: The adversary may upload a ransom note to the S3 bucket or notify the victim through other channels, demanding payment in exchange for the decryption key.

## Impact

The primary impact of this attack is the loss of data availability and integrity for affected S3 objects. Victims face immediate operational disruption due to inaccessible critical business data, leading to potential revenue loss, reputational damage, and compliance violations. The technique is a common form of cloud ransomware, resulting in direct financial loss if a ransom is paid, or significant costs and time for data recovery from backups if no decryption key is obtained. While specific victim counts are not provided, this technique poses a threat to any organization using Amazon S3 for data storage, particularly those with valuable or sensitive information in inadequately protected buckets.

## Recommendation

* Deploy the Sigma rule in this brief to your SIEM and tune it for your environment, focusing on detecting `PutObject` or `CopyObject` events in AWS CloudTrail logs.
* Ensure AWS S3 data event types are enabled in your CloudTrail trail configuration to capture necessary logging for the detection rule.
* Review the `aws.cloudtrail.user_identity.arn` and `source.ip` fields from CloudTrail logs for any alerts generated by the detection rule to identify the user and source of the activity.
* Implement strong IAM policies to restrict S3 `PutObject` and `CopyObject` permissions, especially for SSE-C usage, to only authorized users and roles.
* Enable alerts for future SSE-C encryption attempts in critical S3 buckets to detect deviations from normal operations.
* Rotate affected access keys immediately if unauthorized behavior related to SSE-C encryption is confirmed.
* Regularly audit IAM policies and roles associated with S3 access to ensure least privilege is maintained.

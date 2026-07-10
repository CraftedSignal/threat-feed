---
title: AWS S3 Bucket Policy Added to Allow Public Access
slug: 2024-01-aws-s3-public-access
description: An AWS S3 bucket policy was modified to grant public access using a wildcard (Principal:"*") statement, potentially allowing data exfiltration or malicious content hosting.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - s3
  - exfiltration
  - cloud
vendors:
  - AWS
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
references:
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.exfiltration.s3-backdoor-bucket-policy/
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html
rules:
  - title: AWS S3 Bucket Policy Added to Allow Public Access
    description: Detects when an Amazon S3 bucket policy is modified to grant public access using a wildcard (Principal:"*") statement.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
      - s3.amazonaws.com
  - title: AWS S3 DeleteBucketPolicy Followed by PutBucketPolicy with Public Access
    description: Detects a DeleteBucketPolicy event followed by a PutBucketPolicy event granting public access, indicating a potential attempt to bypass existing protections.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
      - s3.amazonaws.com
rules_count: 2
---

The rule detects modifications to Amazon S3 bucket policies where permissions are extended to all identities, including unauthenticated users, by using a wildcard principal (Principal:"*"). This is achieved via the `PutBucketPolicy` API call with `Effect=Allow`. Publicly exposing an S3 bucket is a common cause of sensitive data leaks in AWS environments. Adversaries or misconfigurations can leverage this exposure to exfiltrate data, host malicious content, or collect credentials and logs left in open storage. This rule focuses on policy-based exposure rather than ACL-based or block-public-access configurations and was initially created on 2025/10/30, with the last update on 2026/04/10. It's crucial to review such changes to prevent unauthorized access and potential data breaches.

## Attack Chain

1. An attacker gains access to an AWS account through compromised credentials or a misconfigured IAM role.
2. The attacker identifies an S3 bucket containing sensitive data.
3. The attacker modifies the bucket policy using the `PutBucketPolicy` API call.
4. The modified bucket policy includes an `Effect=Allow` statement with `Principal:"*"`, granting public access.
5. The attacker (or anyone) can now access the bucket's contents using the S3 API or tools like `aws s3 cp`.
6. The attacker exfiltrates the sensitive data to an external location.
7. Alternatively, the attacker uploads malicious content to the publicly accessible bucket.

## Impact

Publicly exposing an S3 bucket can lead to significant data breaches. Sensitive data, such as customer information, financial records, or proprietary code, can be exfiltrated by unauthorized individuals. This can result in financial losses, reputational damage, and legal liabilities. The number of affected individuals depends on the data stored in the exposed bucket. Sectors storing sensitive data, such as finance, healthcare, and technology, are particularly vulnerable.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unauthorized modifications to S3 bucket policies. Tune the rule to your specific environment to minimize false positives (`index`, `data_stream.dataset`).
*   Review CloudTrail logs for `PutBucketPolicy` events with `Effect=Allow` and `Principal:"*"` to identify potentially misconfigured buckets (`event.action`, `aws.cloudtrail.request_parameters`).
*   Implement AWS Config rules `s3-bucket-public-read-prohibited` and `s3-bucket-public-write-prohibited` to automatically remediate public access issues.
*   Restrict `s3:PutBucketPolicy` permissions to trusted administrative roles to prevent unauthorized policy modifications.
*   Enable AWS Security Hub or GuardDuty for continuous monitoring of public exposure events.

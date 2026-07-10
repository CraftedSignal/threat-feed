---
title: AWS S3 Unauthenticated Bucket Access by Rare Source
slug: 2024-12-aws-s3-unauthenticated-access
description: This rule detects AWS CloudTrail events indicative of unauthenticated sources attempting to access an S3 bucket, potentially exposing sensitive data due to misconfigured bucket policies.
date: "2024-12-17T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - s3
  - unauthenticated-access
  - cloudtrail
  - collection
vendors:
  - AWS
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1619
    technique_name: Cloud Storage Object Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
references:
  - https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
rules:
  - title: AWS S3 Unauthenticated GetObject by Rare Source
    description: Detects unauthenticated GetObject requests to S3 buckets from a rare source IP.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Unauthenticated ListBucket by Rare Source
    description: Detects unauthenticated ListBucket requests to S3 buckets from a rare source IP.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1619
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection rule identifies AWS CloudTrail events where an unauthenticated source is attempting to access an S3 bucket. The activity may indicate a misconfigured S3 bucket policy that allows public access, potentially exposing sensitive data to unauthorized users. Adversaries can specify `--no-sign-request` in the AWS CLI to retrieve objects from an S3 bucket without authentication. This rule triggers for each unique combination of the source IP address and targeted bucket name. S3 data events must be enabled in CloudTrail. The rule is designed to detect anomalous access patterns, specifically unauthenticated requests from rare sources to S3 buckets, helping defenders quickly identify and remediate potential data exposure incidents.

## Attack Chain

1. An attacker identifies a potential target AWS environment and attempts to enumerate publicly accessible S3 buckets.
2. The attacker utilizes tools like the AWS CLI with the `--no-sign-request` option or custom scripts to bypass authentication requirements.
3. The attacker sends a request to list objects in the S3 bucket (ListObjects API call) to understand the bucket's contents.
4. If listing is successful, the attacker attempts to retrieve sensitive objects using GetObject API calls.
5. The attacker downloads the objects to a local system for analysis and potential exfiltration.
6. The attacker might modify or delete objects (PutObject, DeleteObject) if write access is also misconfigured, leading to data manipulation or destruction.
7. The attacker attempts to laterally move within the AWS environment using exposed credentials or configuration files found in the S3 bucket.

## Impact

A successful attack can lead to the exposure of sensitive data stored in S3 buckets, including credentials, intellectual property, or personally identifiable information (PII). This can result in data breaches, compliance violations, and reputational damage. Data manipulation or destruction can also impact business operations and data integrity. The severity depends on the nature and volume of the data exposed, potentially affecting thousands of users or customers.

## Recommendation

*   Enable S3 data events in CloudTrail to capture GetObject, PutObject, ListObjects, and DeleteObject actions (see Setup in rule description).
*   Deploy the Sigma rule "AWS S3 Unauthenticated Bucket Access by Rare Source" to your SIEM and tune the threshold based on your environment to reduce false positives.
*   Review S3 bucket policies and ACLs regularly to ensure they adhere to AWS security best practices. Use AWS Trusted Advisor or Access Analyzer to identify misconfigurations.
*   Enable **S3 Block Public Access** settings to prevent unintended public access as recommended in the rule's response and remediation steps.
*   Configure real-time alerts for unauthenticated GetObject or ListObjects events on sensitive S3 buckets to detect and respond to unauthorized access attempts.

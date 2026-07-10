---
title: AWS CLI Activity Detection for Open S3 Bucket Creation
slug: 2024-01-open-s3-buckets
description: Detection of S3 bucket creation via AWS CLI which might lead to data exposure and unauthorized access.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - s3
  - cloud
  - data-breach
vendors:
  - Amazon
products:
  - Amazon S3
  - AWS Command Line Interface
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1530
    technique_name: Cloud Service Discovery
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/detect_new_open_s3_buckets_over_aws_cli.yml
rules:
  - title: Detect S3 Bucket Creation with Public ACL via AWS CLI
    description: Detects the creation of an S3 bucket with a public ACL using the AWS CLI, indicating a potential misconfiguration leading to data exposure.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Public ACL Modification on S3 Bucket via AWS CLI
    description: Detects the modification of an S3 bucket's ACL to public-read or public-read-write using the AWS CLI.
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

This brief focuses on detecting the creation of publicly accessible Amazon S3 buckets using the AWS Command Line Interface (CLI). While not inherently malicious, creating open S3 buckets can lead to significant data breaches if sensitive information is stored within them. Monitoring AWS CLI usage for S3 bucket creation is crucial for preventing unintentional exposure of data. This activity is often part of a larger attack chain, where adversaries attempt to identify and exploit misconfigured cloud resources for data theft or other malicious purposes. Understanding how these buckets are created and configured allows defenders to identify and remediate potential risks before they are exploited.

## Attack Chain

1.  Attacker gains initial access to an AWS account, potentially through compromised credentials or a misconfigured IAM role.
2.  Attacker uses the AWS CLI to interact with the AWS environment.
3.  The attacker utilizes the `aws s3api create-bucket` command to create a new S3 bucket.
4.  The attacker then uses the `aws s3api put-bucket-acl` command to set the bucket's Access Control List (ACL) to `public-read` or `public-read-write`, making the bucket publicly accessible.
5.  Alternatively, the attacker may use `aws s3api put-bucket-policy` to configure a bucket policy that allows public access.
6.  The attacker uploads data to the publicly accessible S3 bucket.
7.  The attacker may then attempt to exfiltrate data from other AWS resources into the newly created, open S3 bucket before final exfiltration.
8.  The ultimate goal is to exfiltrate sensitive data or use the open bucket as a staging ground for further attacks.

## Impact

The impact of creating open S3 buckets can be severe. Data stored in publicly accessible buckets can be easily accessed by anyone on the internet, leading to data breaches, compliance violations, and reputational damage. Depending on the data stored, this can affect thousands or millions of users. Organizations in all sectors, including healthcare, finance, and government, are potential targets. A successful attack can result in the loss of sensitive personal information, financial data, intellectual property, and other confidential information.

## Recommendation

*   Deploy the "Detect New Open S3 Buckets Over AWS CLI" Sigma rule to your SIEM and tune for your environment to detect suspicious bucket creation activity.
*   Monitor AWS CloudTrail logs for `CreateBucket` and `PutBucketAcl` events to detect S3 bucket creation and ACL modifications.
*   Implement and enforce least privilege IAM policies to restrict who can create and modify S3 buckets, and limit the ability to make them public.
*   Regularly audit S3 bucket permissions to identify and remediate any publicly accessible buckets.

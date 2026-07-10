---
title: AWS KMS Key User Performing S3 Encryption
slug: 2024-01-aws-kms-s3-encryption
description: Detection of AWS users employing KMS keys for S3 encryption, potentially indicating suspicious data handling within cloud environments.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - kms
  - s3
  - cloud
  - encryption
vendors:
  - AWS
products:
  - AWS Identity and Access Management
  - AWS Key Management Service
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_detect_users_with_kms_keys_performing_encryption_s3.yml
rules:
  - title: Detect KMS Key Usage for S3 Encryption
    description: Detects IAM users utilizing KMS keys to encrypt S3 objects.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - cloudtrail
      - aws
  - title: Detect S3 Bucket Encryption Configuration with KMS
    description: Detects changes to S3 bucket encryption configuration to use KMS keys.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1486
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection focuses on identifying AWS Identity and Access Management (IAM) users who are actively utilizing Key Management Service (KMS) keys to encrypt data within Simple Storage Service (S3) buckets. While not inherently malicious, such activity warrants monitoring as it could signify insider threats, compromised accounts, or unauthorized data handling procedures. Attackers might leverage stolen credentials or compromised IAM roles to encrypt data using KMS, potentially as a precursor to data exfiltration or ransomware-like activity targeting cloud storage. This activity should be considered especially concerning if the KMS keys being used are outside the user's normal operational scope.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account, either through compromised credentials or exploiting a misconfigured IAM role.
2. The attacker enumerates available S3 buckets and identifies a target bucket containing sensitive data.
3. The attacker identifies or creates a KMS key within the AWS environment.
4. The attacker configures the target S3 bucket to use the identified KMS key for encryption of objects stored within it.
5. The attacker uploads or modifies objects within the S3 bucket, triggering encryption using the KMS key.
6. The attacker attempts to exfiltrate the encrypted data.

## Impact

Successful exploitation could lead to unauthorized access to sensitive data stored within S3 buckets. Depending on the nature of the data, this could result in financial losses, reputational damage, and legal repercussions. Furthermore, if the attacker controls the KMS key, they could render the data inaccessible, effectively holding it hostage. The impact can vary based on the scope of the compromised data and the attacker's objectives, potentially affecting customer data, intellectual property, or critical business information.

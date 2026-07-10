---
title: New Publicly Accessible S3 Bucket Detection
slug: 2024-01-open-s3-buckets
description: This brief focuses on detecting the creation of new, publicly accessible Amazon S3 buckets, potentially indicating misconfigured security settings or malicious intent to expose data.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - s3
  - aws
  - data-leakage
vendors:
  - Amazon
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1530
    technique_name: Data Source Visibility
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/detect_new_open_s3_buckets.yml
rules:
  - title: Detect S3 Bucket Created with Public Read ACL
    description: Detects the creation of an S3 bucket with a public read ACL, which can lead to data exposure.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect S3 Bucket ACL Modified to Public Read
    description: Detects modification of an existing S3 bucket's ACL to grant public read access.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The creation of publicly accessible Amazon S3 buckets can lead to significant data breaches if sensitive information is inadvertently exposed. While the provided source material focuses solely on the detection aspect, the underlying threat involves potential misconfigurations or malicious actions leading to data exposure. An attacker might intentionally create open buckets to stage data for exfiltration, or an insider might misconfigure a bucket allowing unintended public access. The provided Splunk detection rule aims to identify these newly created open buckets, allowing security teams to promptly remediate the issue. The rule is contained in `detect_new_open_s3_buckets.yml` from the `splunk-escu` project.

## Attack Chain

Since the source focuses on detection, this attack chain is based on potential misconfiguration or malicious intent that leads to publicly accessible S3 buckets.

1. **Initial Compromise (Optional):** An attacker gains initial access to a cloud environment through compromised credentials, a vulnerable application, or other means.
2. **Privilege Escalation (Optional):** The attacker escalates privileges within the cloud environment to gain the ability to create and modify S3 buckets.
3. **S3 Bucket Creation:** The attacker creates a new S3 bucket using the AWS CLI, SDK, or console.
4. **ACL Modification:** The attacker modifies the Access Control List (ACL) of the S3 bucket to grant public read and/or write access. This is the critical misconfiguration or malicious act.
5. **Data Upload:** Sensitive data is uploaded to the newly created, publicly accessible S3 bucket. This data could include PII, financial records, proprietary source code, or other confidential information.
6. **Data Discovery (by Attacker/External Party):** The attacker themselves, or an external party, discovers the publicly accessible S3 bucket, potentially through automated scanning or accidental discovery.
7. **Data Exfiltration:** The data is exfiltrated from the S3 bucket by the attacker or other unauthorized parties.
8. **Impact:** The exfiltrated data is used for malicious purposes, such as identity theft, financial fraud, extortion, or competitive advantage.

## Impact

The impact of a publicly accessible S3 bucket can be severe. A single misconfigured bucket can expose vast amounts of sensitive data, leading to regulatory fines, legal liabilities, reputational damage, and financial losses. Organizations across all sectors that utilize cloud storage are potential victims. The severity of the impact depends on the nature and volume of data exposed. A successful attack can result in millions of dollars in losses and long-lasting damage to the organization's reputation.

## Recommendation

*   Deploy the Sigma rule to your SIEM to detect the creation of publicly accessible S3 buckets and tune it for your environment.
*   Implement automated checks and policies to prevent the creation of publicly accessible S3 buckets by default. Regularly audit existing buckets for misconfigurations.
*   Review IAM policies to ensure that only authorized personnel have the ability to create and modify S3 bucket ACLs.
*   Enable and monitor cloud provider logging (e.g., CloudTrail) to capture all S3 bucket creation and modification events.

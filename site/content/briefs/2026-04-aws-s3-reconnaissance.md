---
title: AWS S3 Rapid Bucket Posture API Calls Indicate Reconnaissance
slug: 2026-04-aws-s3-reconnaissance
description: An AWS principal rapidly enumerates S3 bucket configurations using read-only APIs, potentially indicating reconnaissance activity by security scanners, CSPM tools, or malicious actors performing post-compromise enumeration.
date: "2026-04-11T12:00:00Z"
severities:
  - low
tags:
  - cloud
  - aws
  - s3
  - reconnaissance
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1619
    technique_name: Cloud Storage Object Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
references:
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
  - https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.pdf
  - https://github.com/aws-samples/aws-incident-response-playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework
rules:
  - title: AWS S3 Rapid Bucket Enumeration
    description: Detects rapid enumeration of S3 buckets by an AWS principal, indicating potential reconnaissance.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - cloudtrail
      - aws
  - title: AWS S3 Rapid Bucket Enumeration by Service Account
    description: Detects rapid enumeration of S3 buckets by an AWS Service Account, indicating potential CSPM or authorized scanning activity.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief details detection of rapid enumeration of AWS S3 bucket configurations. The activity is characterized by an AWS principal invoking read-only S3 control-plane APIs across numerous buckets within a short timeframe. This pattern is consistent with automated reconnaissance, security scanning, or post-compromise enumeration. The activity is detected by monitoring AWS CloudTrail logs for specific API calls such as `GetBucketAcl`, `GetBucketPublicAccessBlock`, `GetBucketPolicy`…

---
title: AWS S3 Rapid Bucket Posture API Calls Indicate Reconnaissance
slug: 2026-04-aws-s3-reconnaissance
description: An AWS principal rapidly enumerates S3 bucket configurations using read-only APIs, potentially indicating reconnaissance activity by security scanners, CSPM tools, or malicious actors performing post-compromise enumeration.
date: "2026-04-11T12:00:00Z"
type: advisory
types:
  - advisory
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

This threat brief details detection of rapid enumeration of AWS S3 bucket configurations. The activity is characterized by an AWS principal invoking read-only S3 control-plane APIs across numerous buckets within a short timeframe. This pattern is consistent with automated reconnaissance, security scanning, or post-compromise enumeration. The activity is detected by monitoring AWS CloudTrail logs for specific API calls such as `GetBucketAcl`, `GetBucketPublicAccessBlock`, `GetBucketPolicy`, `GetBucketPolicyStatus`, and `GetBucketVersioning`. The detection logic excludes AWS service principals and sessions using Management Console credentials to reduce false positives. This activity is relevant for defenders as it can signal early-stage reconnaissance by threat actors like Team PCP, or unauthorized data discovery within the AWS environment. The rule uses a threshold of 15 distinct buckets accessed within 10 seconds to identify suspicious behavior.

## Attack Chain

1. An attacker gains access to AWS credentials, possibly through compromised credentials or misconfigured IAM roles.
2. The attacker uses the acquired credentials to authenticate to the AWS environment.
3. The attacker executes a script or tool that calls multiple S3 APIs (e.g., `GetBucketAcl`, `GetBucketPolicy`) to gather information about S3 buckets.
4. The tool iterates through a list of buckets, querying the configuration of each.
5. The attacker collects the responses from the S3 API calls, mapping out bucket names, permissions, and access control lists.
6. The attacker analyzes the collected data to identify potentially sensitive data or misconfigured buckets.
7. Based on the findings, the attacker may proceed to exfiltrate data from accessible buckets (T1530).
8. The attacker may also attempt to modify bucket policies or access controls to gain further access or persistence.

## Impact

Successful reconnaissance of S3 bucket configurations allows attackers to identify vulnerable buckets, potentially leading to data breaches or unauthorized access to sensitive information. The source material does not provide specific victim counts or sectors. However, the impact can range from exposure of confidential data to full compromise of the AWS environment, depending on the level of access gained and the sensitivity of the data stored in the targeted buckets. Identifying the activity early can prevent further exploitation.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect rapid S3 bucket posture API calls (see: "AWS S3 Rapid Bucket Enumeration").
*   Review IAM policies and enforce least privilege on S3 read APIs to limit the scope of potential reconnaissance activities.
*   Monitor CloudTrail logs for the same `aws.cloudtrail.user_identity.arn` and `source.ip` within approximately ±30 minutes for follow-on patterns such as `ListBuckets`, `GetObject`, `PutBucketPolicy`, or `AssumeRole` activities (see Overview).
*   Rotate or disable keys for the affected identity, revoke active role sessions where possible, and restrict the source IP at the network layer if it is not authorized (see Overview).
*   Whitelist approved scanning accounts and tune the Sigma rule to reduce noise from those identities (see Overview).

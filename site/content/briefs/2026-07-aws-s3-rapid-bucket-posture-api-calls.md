---
title: AWS S3 Rapid Bucket Posture API Calls from a Single Principal
slug: 2026-07-aws-s3-rapid-bucket-posture-api-calls
description: This detection rule identifies suspicious activity in AWS environments where a single principal, from a consistent source IP, rapidly performs read-only S3 control-plane API calls across more than 15 distinct S3 buckets within a 10-second window, indicative of automated reconnaissance, security scanning, or post-compromise enumeration aiming to map S3 bucket access, policies, and versioning.
date: "2026-07-20T13:09:51Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - s3
  - cloudtrail
  - discovery
  - collection
  - reconnaissance
  - cloud
vendors:
  - Amazon
products:
  - S3
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: This pattern can indicate automated reconnaissance or security scanning... often walk many buckets quickly to map public access, policies, and versioning.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
    evidence: This pattern can indicate automated reconnaissance or security scanning... often walk many buckets quickly to map public access, policies, and versioning.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1619
    technique_name: Cloud Storage Object Discovery
    evidence: Identifies when the same AWS principal, from the same source IP, successfully invokes read-only S3 control-plane APIs that reveal bucket posture across many buckets in a short period.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: The gathered S3 bucket posture information is used to plan subsequent actions, such as targeting specific buckets for data collection (`GetObject`).
    confidence_band: med
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_s3_rapid_bucket_posture_api_calls.toml
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
---

This brief describes a detection rule designed to identify AWS S3 reconnaissance activity where a single principal, originating from the same source IP address, executes a high volume of read-only S3 control-plane API calls across numerous distinct S3 buckets within a very short timeframe. Specifically, the rule flags more than 15 distinct S3 bucket posture API calls, such as `GetBucketAcl`, `GetBucketPublicAccessBlock`, `GetBucketPolicy`, `GetBucketPolicyStatus`, and `GetBucketVersioning`, within a 10-second window. This pattern is often associated with automated security scanning tools, Cloud Security Posture Management (CSPM) products, or post-compromise enumeration attempts by threat actors like Team PCP seeking to map an organization's S3 assets and identify potential misconfigurations. The detection explicitly filters out AWS service principals and focuses on programmatic sessions rather than AWS Management Console activity, requiring valid resource and identity fields for accurate cardinality.

## Attack Chain

1. **Initial Compromise / Credential Access:** An attacker obtains valid AWS credentials or assumes an authorized identity, typically through methods such as phishing, exploiting a vulnerable application, finding exposed access keys, or compromising an endpoint.
2. **Cloud Environment Discovery:** Using the compromised credentials, the attacker initiates reconnaissance to understand the target AWS environment and identify potentially valuable resources for further exploitation.
3. **S3 Bucket Posture Enumeration:** The attacker specifically targets Amazon S3, executing a rapid sequence of read-only control-plane API calls to gather detailed configuration and policy information about various S3 buckets.
4. **Automated Scanning:** These API calls, including `GetBucketAcl`, `GetBucketPublicAccessBlock`, `GetBucketPolicy`, `GetBucketPolicyStatus`, and `GetBucketVersioning`, are performed programmatically from a single source IP address, often via tools like the AWS CLI or SDKs. The activity involves querying more than 15 distinct S3 buckets within a 10-second window.
5. **Information Gathering:** The goal is to identify S3 buckets with misconfigured permissions, public access, vulnerable versioning policies, or sensitive data, which could lead to unauthorized data access, modification, or exfiltration.
6. **Preparation for Data Collection/Exfiltration:** The attacker leverages the gathered S3 bucket posture information to plan subsequent actions, such as targeting specific buckets for data retrieval (`GetObject`) or attempting to modify bucket policies (`PutBucketPolicy`) to facilitate data exfiltration.

## Impact

Undetected rapid S3 bucket reconnaissance allows attackers to gain a comprehensive understanding of an organization's cloud storage assets and their security posture. This knowledge enables them to pinpoint misconfigured buckets, identify publicly exposed data, and locate sensitive information, which can then be leveraged for further attacks. The success of such reconnaissance can directly lead to unauthorized access to confidential data, data exfiltration, data tampering or deletion, and potential resource hijacking. These outcomes can result in significant financial losses, severe reputational damage, and major regulatory compliance violations, particularly if personal, financial, or proprietary data is compromised. Early detection, as provided by this rule, is crucial to prevent the progression to more damaging attack stages.

## Recommendation

* Review AWS CloudTrail logs to identify the `aws.cloudtrail.user_identity.arn` and `source.ip` associated with any alerts, and determine if the activity is from an approved security scanner or inventory tool.
* Investigate the `Esql.aws_cloudtrail_resources_arn_values` to understand which specific S3 buckets were targeted and prioritize investigation for those containing sensitive or critical data.
* Query CloudTrail for the same `aws.cloudtrail.user_identity.arn` and `source.ip` within approximately ±30 minutes of the alert timestamp to identify any follow-on patterns, such as `ListBuckets`, `GetObject`, `PutBucketPolicy`, `AssumeRole`, or IAM changes.
* Enforce least privilege on S3 read APIs; use permission boundaries or Service Control Policies where appropriate to limit the scope of S3 access for all IAM principals.
* Document approved security scanning accounts and tune the detection rule to reduce noise from legitimate, expected activities.

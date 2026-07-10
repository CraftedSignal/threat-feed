---
title: Rapid Enumeration of AWS S3 Buckets via API Calls
slug: 2024-01-09-aws-s3-bucket-reconnaissance
description: An AWS principal from a single source IP rapidly invokes read-only S3 control-plane APIs, revealing bucket posture across many buckets in a short time, potentially indicating automated reconnaissance or post-compromise enumeration.
date: "2024-01-09T17:34:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - cloudtrail
  - s3
  - reconnaissance
vendors:
  - AWS
products:
  - Amazon S3
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
  - title: AWS S3 Rapid Bucket Posture API Calls
    description: Detects rapid enumeration of AWS S3 buckets via read-only control-plane API calls from a single principal, potentially indicating reconnaissance activity.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1526
      - T1580
      - T1619
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS S3 Bucket Policy Changes After Rapid Enumeration
    description: Detects changes in S3 bucket policy (PutBucketPolicy, DeleteBucketPolicy) shortly after rapid enumeration, potentially indicating exploitation.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - discovery
    techniques:
      - T1526
      - T1530
      - T1580
      - T1619
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

This rule detects potential reconnaissance activity in AWS environments where an AWS principal, originating from a single IP address, rapidly enumerates multiple S3 buckets using read-only control-plane APIs. This behavior is characterized by the successful invocation of APIs such as `GetBucketAcl`, `GetBucketPublicAccessBlock`, `GetBucketPolicy`, `GetBucketPolicyStatus`, and `GetBucketVersioning` across more than 15 distinct S3 buckets within a 10-second window. The detection excludes AWS service principals and activity associated with Management Console credentials, focusing on programmatic-style access. Such rapid enumeration is often associated with automated security scanning, CSPM tooling, or post-compromise reconnaissance, potentially mirroring techniques used by threat actors performing cloud service discovery, as highlighted in reports about Team PCP.

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials or an exposed access key.
2.  The attacker uses the AWS CLI or a custom script to interact with the AWS environment programmatically.
3.  The attacker iterates through a list of AWS S3 buckets within the target environment.
4.  For each S3 bucket, the attacker invokes read-only S3 control-plane APIs, such as `GetBucketAcl`, `GetBucketPublicAccessBlock`, `GetBucketPolicy`, `GetBucketPolicyStatus`, and `GetBucketVersioning`.
5.  The attacker collects information about bucket configurations, access controls, and policies.
6.  The collected data is analyzed to identify publicly accessible buckets, misconfigurations, or sensitive data.
7.  The attacker may then attempt to exploit identified vulnerabilities or access sensitive data stored in the buckets (Data from Cloud Storage - T1530).
8.  The attacker uses discovered information to move laterally within the cloud environment or exfiltrate sensitive data.

## Impact

Successful reconnaissance of S3 buckets can expose sensitive data, misconfigurations, and vulnerabilities within an AWS environment. An attacker who successfully identifies publicly accessible buckets or buckets with overly permissive access controls may be able to access and exfiltrate sensitive data, escalate privileges, or move laterally within the cloud environment. The number of potentially affected buckets and the severity of the impact will vary depending on the scale and sensitivity of the data stored in the target AWS environment. This can lead to data breaches, compliance violations, and financial losses.

## Recommendation

*   Enable AWS CloudTrail logging to capture API activity within your AWS environment.
*   Deploy the Sigma rule `AWS S3 Rapid Bucket Posture API Calls` to your SIEM and tune the threshold (currently 15 buckets in 10 seconds) for your environment.
*   Investigate any alerts generated by the Sigma rule by reviewing the `aws.cloudtrail.user_identity.arn` and `source.ip` associated with the activity, as described in the rule's description.
*   Enforce least privilege on S3 read APIs; use permission boundaries or service control policies where appropriate. Refer to the "Harden" section in the rule's description for additional hardening guidance.
*   Document approved scanning accounts and tune the rule to reduce noise from those identities. Implement `user_agent` filters if necessary, based on analysis of the `user_agent.original` field in CloudTrail logs.

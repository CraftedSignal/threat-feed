---
title: AWS EC2 Role GetCallerIdentity from New Source AS Organization
slug: 2024-01-02-aws-ec2-role-getcalleridentity
description: The rule detects when an EC2 instance role session calls AWS STS GetCallerIdentity from a new source autonomous system (AS) organization name, indicating potential credential theft and verification from outside expected egress paths.
date: "2026-05-01T20:57:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - getcalleridentity
  - ec2
  - discovery
vendors:
  - Amazon
  - Google
  - MongoDB, Inc.
products:
  - Amazon Web Services
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
references:
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
  - https://detectioninthe.cloud/ttps/discovery/sts_get_caller_identity
rules:
  - title: AWS EC2 Role GetCallerIdentity from New Source AS Organization
    description: Detects when an EC2 instance role session calls AWS STS GetCallerIdentity from a new source autonomous system (AS) organization name.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087
      - T1087.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Instance without Amazon ASN Calling GetCallerIdentity
    description: This rule detects the unusual behavior of EC2 instances calling the AWS STS GetCallerIdentity API when not using an Amazon ASN, which may indicate credential compromise.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when an EC2 instance role session calls the AWS STS GetCallerIdentity API from a source Autonomous System (AS) Organization name that has not been previously observed. The GetCallerIdentity API is often used by adversaries to validate stolen instance role credentials from infrastructure outside the victim's normal egress points. By baselining the combination of identity and source network, the rule reduces noise associated with stable NAT or AWS-classified egress, focusing on truly novel access patterns. This detection is specifically designed to complement other rules that may detect general GetCallerIdentity calls, by excluding previously seen combinations of user identity and source AS organization.

## Attack Chain

1. An attacker gains unauthorized access to an EC2 instance through methods like exploiting a Server-Side Request Forgery (SSRF) vulnerability, compromising application code or exploiting IMDS abuse.
2. The attacker leverages the instance's IAM role to obtain temporary AWS credentials.
3. The attacker attempts to validate the stolen credentials using the `GetCallerIdentity` API call.
4. The `GetCallerIdentity` API call originates from an IP address associated with a new and unexpected Autonomous System Organization (ASO).
5. The AWS CloudTrail logs record the `GetCallerIdentity` event, including the user identity ARN and the source AS organization name.
6. The detection rule triggers due to the new combination of user identity and source AS organization.
7. The attacker uses the validated credentials to perform reconnaissance and identify valuable resources within the AWS environment (e.g., S3 buckets, databases).
8. The attacker attempts to exfiltrate sensitive data or deploy malicious workloads using the stolen credentials.

## Impact

A successful attack can lead to unauthorized access to sensitive data stored within the AWS environment. The attacker may be able to escalate privileges, compromise other resources, and disrupt services. The potential impact includes data breaches, financial loss, and reputational damage. The lack of specific victim counts or sectors targeted suggests a broad applicability across various AWS users.

## Recommendation

*   Deploy the Sigma rule "AWS EC2 Role GetCallerIdentity from New Source AS Organization" to your SIEM to detect suspicious activity.
*   Investigate alerts triggered by the Sigma rule, focusing on the `aws.cloudtrail.user_identity.arn` and `source.as.organization.name` fields.
*   Monitor AWS CloudTrail logs for `GetCallerIdentity` API calls, particularly those originating from unfamiliar source IP addresses and ASNs.
*   Revoke compromised IAM role sessions by stopping the affected EC2 instances or removing the role from the instance profile.
*   Rotate any long-lived secrets accessible by the EC2 instance, based on the `aws.cloudtrail.user_identity.access_key_id`.

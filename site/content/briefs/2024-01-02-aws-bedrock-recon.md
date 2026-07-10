---
title: High Number of AWS Bedrock List Foundation Model Failures
slug: 2024-01-02-aws-bedrock-recon
description: Detection of a high number of AccessDenied errors when attempting to list AWS Bedrock foundation models, indicating potential reconnaissance activity after credential compromise to discover accessible AI models.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - bedrock
  - reconnaissance
  - cloudtrail
vendors:
  - AWS
products:
  - Bedrock
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://docs.aws.amazon.com/bedrock/latest/APIReference/API_ListFoundationModels.html
  - https://trustoncloud.com/blog/exposing-the-weakness-how-we-identified-a-flaw-in-bedrocks-foundation-model-access-control/
  - https://attack.mitre.org/techniques/T1595/
rules:
  - title: Detect High Number of AWS Bedrock ListFoundationModels Failures
    description: Detects a high number of AccessDenied errors when calling ListFoundationModels API, indicating potential reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Bedrock ListFoundationModels Success Followed by AccessDenied
    description: Detects successful calls to ListFoundationModels followed by AccessDenied errors, which may indicate privilege escalation attempts.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic identifies potential reconnaissance activity against AWS Bedrock by detecting a high number of `AccessDenied` errors when calling the `ListFoundationModels` API. The activity is significant because it suggests an attacker, potentially with compromised credentials and limited permissions, is attempting to enumerate available AI models. Multiple failed attempts could signify brute-force attempts to bypass access controls or indicate misconfigured IAM policies. The detection focuses on identifying patterns of failed API calls using AWS CloudTrail logs. This early-stage reconnaissance is a precursor to potentially accessing or manipulating Bedrock models or knowledge bases. The detection looks for more than 9 attempts.

## Attack Chain

1.  Compromise of AWS credentials with limited permissions.
2.  Attacker uses the compromised credentials to call the `ListFoundationModels` API via the AWS CLI or SDK.
3.  Due to insufficient permissions, the API calls return an `AccessDenied` error.
4.  The attacker repeats the `ListFoundationModels` API calls multiple times, attempting to bypass access controls or discover accessible models.
5.  AWS CloudTrail logs record each `ListFoundationModels` API call and the corresponding `AccessDenied` error, including the source IP address, user agent, and user name.
6.  A detection rule identifies the high number of `AccessDenied` errors within a specific timeframe.
7.  Successful enumeration of foundation models allows the attacker to plan subsequent attacks, such as accessing models or manipulating knowledge bases.

## Impact

A successful attack can lead to unauthorized access to or manipulation of AWS Bedrock foundation models. This can result in data breaches, model poisoning, or the use of AI models for malicious purposes. While the number of affected organizations is currently unknown, the impact could be significant, especially for organizations relying on Bedrock for critical AI applications.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect a high number of `AccessDenied` errors for `ListFoundationModels` in AWS CloudTrail logs.
*   Investigate identified users and source IP addresses exhibiting a high number of failed `ListFoundationModels` API calls.
*   Review and harden IAM policies to ensure proper access controls for AWS Bedrock services.
*   Implement multi-factor authentication (MFA) to protect AWS credentials.

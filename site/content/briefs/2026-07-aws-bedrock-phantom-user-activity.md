---
title: AWS Bedrock API Key Phantom User Activity Outside Bedrock
slug: 2026-07-aws-bedrock-phantom-user-activity
description: An Amazon Bedrock API key phantom user (IAM user starting with 'BedrockAPIKey-*') performing non-Bedrock API calls, such as to IAM, STS, EC2, VPC, or KMS, indicates credential misuse and realized privilege escalation by an attacker using added standard IAM access keys for reconnaissance or lateral movement beyond the intended Bedrock authentication boundary.
date: "2026-07-08T21:46:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - privilege-escalation
  - aws
  - bedrock
  - iam
vendors:
  - Amazon
products:
  - AWS Bedrock
  - AWS IAM
  - AWS STS
  - AWS EC2
  - AWS VPC
  - AWS KMS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: 'A phantom user performing activity outside of Bedrock indicates its credentials are being used beyond their intended scope, which is the privilege-escalation path realized: an attacker who created standard IAM access keys for the phantom user is now using them for reconnaissance or lateral movement outside the Bedrock authentication boundary.'
    confidence_band: high
references:
  - https://www.beyondtrust.com/blog/entry/aws-bedrock-security-guide-api-keys-detection-response
  - https://www.beyondtrust.com/blog/entry/aws-bedrock-security-api-keys
  - https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html
rules:
  - title: AWS Bedrock API Key Phantom User Activity Outside Bedrock
    description: Identifies an Amazon Bedrock API key phantom user (an IAM user whose name starts with 'BedrockAPIKey-') acting as the caller of a non-Bedrock API request, such as IAM, STS, EC2, VPC, or KMS calls. This indicates credential misuse and potential privilege escalation beyond the intended Bedrock authentication boundary.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 1
---

This threat brief details a privilege escalation scenario involving the misuse of Amazon Bedrock API key phantom users within an AWS environment. These phantom users, identified by names starting with "BedrockAPIKey-", are automatically provisioned by AWS to support Bedrock bearer tokens and come with the `AmazonBedrockLimitedAccess` managed policy. While this policy grants Bedrock control-plane actions, it also inadvertently allows reconnaissance capabilities across IAM, VPC, and KMS services. An attacker who has already gained initial access to the AWS account can exploit this by creating standard IAM access keys or a console login for these phantom users. Once these credentials are obtained, the attacker can leverage the phantom user's inherent permissions to perform reconnaissance, gather information, and potentially move laterally beyond the Bedrock authentication boundary, extending their access and control over the AWS infrastructure. This activity represents a realized privilege escalation, enabling broader access than initially intended for an inference-only Bedrock API key.

## Attack Chain

1. Attacker gains initial access to an AWS account or role with permissions to create or modify IAM user credentials (e.g., `iam:CreateAccessKey`, `iam:CreateLoginProfile`).
2. Attacker identifies an existing AWS Bedrock API key phantom user (an IAM user whose name starts with "BedrockAPIKey-*").
3. Attacker creates new standard IAM access keys or a console login profile for the targeted "BedrockAPIKey-*" phantom user.
4. Attacker obtains the newly created IAM access keys or console login credentials.
5. Attacker uses the compromised "BedrockAPIKey-*" credentials to make API calls to non-Bedrock AWS services (e.g., IAM, EC2, STS, VPC, KMS) for reconnaissance and enumeration of resources.
6. Based on the information gathered during reconnaissance, the attacker performs lateral movement, accesses sensitive resources, or exfiltrates data from the AWS environment.

## Impact

If this attack succeeds, an attacker can significantly expand their foothold within an AWS environment. By leveraging the `AmazonBedrockLimitedAccess` policy, which includes reconnaissance permissions for IAM, VPC, and KMS, the attacker can enumerate critical cloud resources and identify potential targets for further compromise. This bypasses the intended scope of the Bedrock API key, allowing unauthorized access to services and data beyond Bedrock. The consequence can range from unauthorized data exposure and modification to complete compromise of critical cloud infrastructure, leading to operational disruption, financial loss, and compliance failures. The attack can affect any AWS account using Bedrock API keys where the ability to create new credentials for phantom users is not adequately restricted.

## Recommendation

* Deploy the Sigma rule "AWS Bedrock API Key Phantom User Activity Outside Bedrock" to your SIEM to detect when `BedrockAPIKey-*` users make API calls to non-Bedrock services.
* Investigate alerts from the Sigma rule by reviewing `aws.cloudtrail.user_identity.arn`, `event.provider`, and `event.action` to understand the scope of the non-Bedrock activity.
* Inspect `source.ip` and `user_agent.original` for reported phantom user activity to identify the source of the anomalous calls and determine if standard IAM access keys or a login profile are being used.
* Correlate anomalous phantom user activity with `CreateAccessKey` or `CreateLoginProfile` events for the same `BedrockAPIKey-*` user to identify the escalation pivot.
* If unauthorized activity is confirmed, disable and remove the phantom user's IAM access keys and login profile.
* Deploy AWS Service Control Policies (SCPs) to deny `iam:CreateAccessKey` and `iam:CreateLoginProfile` actions on resources matching the `arn:aws:iam::*:user/BedrockAPIKey-*` pattern to prevent this privilege escalation path.

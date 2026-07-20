---
title: AWS CLI Discovery from Single Resource
slug: 2026-07-aws-discovery-cli-resource
description: An Elastic detection rule identifies when a single AWS identity, using the AWS CLI, performs more than five distinct read-only discovery API calls (such as Describe*, List*, Get*, and Generate*) across various AWS services within a 10-second window, indicating reconnaissance by an adversary using compromised credentials or an exploited EC2 instance to map the AWS infrastructure for potential targets and further exploitation.
date: "2026-07-20T13:07:53Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - discovery
  - reconnaissance
  - cli
vendors:
  - Amazon
products:
  - AWS
  - AWS CloudTrail
  - Amazon EC2
  - AWS IAM
  - Amazon S3
  - AWS KMS
  - Amazon RDS
  - AWS Lambda
  - Amazon DynamoDB
  - Amazon CloudFront
  - AWS Elastic Load Balancing
  - AWS Organizations
  - AWS STS
  - AWS SES
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: This behavior could indicate an actor attempting to discover the AWS infrastructure using compromised credentials or a compromised instance.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: This behavior could indicate an actor attempting to discover the AWS infrastructure using compromised credentials or a compromised instance.
    confidence_band: high
references:
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
  - https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.pdf
  - https://github.com/aws-samples/aws-incident-response-playbooks/tree/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks
  - https://github.com/aws-samples/aws-customer-playbook-framework
---

An Elastic detection rule flags suspicious AWS CloudTrail activity where a single AWS resource executes more than five unique discovery API calls (e.g., `Describe*`, `List*`, `Get*`, `Generate*`) within a 10-second window. This behavior, often originating from the AWS Command Line Interface (CLI), is a strong indicator of an adversary performing reconnaissance after gaining initial access through compromised credentials or an exploited EC2 instance. Threat actors leverage such rapid, diverse API enumeration to map the target's AWS infrastructure, identify valuable assets, and pinpoint potential weak points for subsequent exploitation. This activity represents an early stage of compromise, providing valuable insights into the attacker's understanding of the environment and their potential next moves. Organizations should prioritize investigation of such alerts to prevent deeper intrusions and data exfiltration.

## Attack Chain

1. **Initial Access**: An attacker gains initial access to an AWS environment, typically via compromised AWS credentials (e.g., IAM user access keys) or by compromising an existing EC2 instance.
2. **Environment Setup**: From the compromised resource or system, the attacker utilizes the AWS Command Line Interface (CLI) to interact with the AWS API.
3. **Broad Enumeration**: The attacker begins to execute multiple read-only API calls across various AWS services such as EC2, IAM, S3, KMS, RDS, Lambda, DynamoDB, CloudFront, Elastic Load Balancing, STS, SES, and Organizations.
4. **Rapid Discovery**: Within a brief 10-second window, the attacker executes more than five distinct API actions, specifically focusing on `Describe*`, `List*`, `Get*`, and `Generate*` operations to gather information.
5. **Information Gathering**: The attacker collects extensive details about the AWS environment, including running instances, user roles, bucket configurations, key management service details, and other resource metadata.
6. **Target Identification**: The gathered information is then used to build a comprehensive understanding of the infrastructure, identify valuable data stores, discover misconfigurations, and pinpoint specific targets for further privilege escalation, lateral movement, or data exfiltration.

## Impact

If this discovery phase succeeds undetected, attackers can gain a deep understanding of the targeted AWS infrastructure, enabling them to identify critical assets, sensitive data, and exploitable misconfigurations. This knowledge significantly facilitates subsequent stages of an attack, such as privilege escalation, lateral movement, data exfiltration, or resource hijacking for cryptocurrency mining. The impact can range from unauthorized data access and financial loss to complete compromise of cloud environments, disruption of services, and reputational damage. While this specific detection identifies an early reconnaissance phase, its successful execution directly increases the likelihood and severity of subsequent, more damaging attacks.

## Recommendation

* Deploy the provided ESQL detection logic (or similar behavioral analytics) to your SIEM, focusing on `aws.cloudtrail` logs, to detect multiple distinct discovery API calls within short timeframes.
* Monitor `aws.cloudtrail` logs for `user_agent.name` indicating `aws-cli` and evaluate its behavior, especially from `source.ip` that are external or unusual for the identity.
* Investigate alerts by examining the `aws.cloudtrail.user_identity.arn` to determine if the activity is legitimate automation or an unexpected identity.
* Review the `event.action` and `event.provider` values in flagged incidents to understand which AWS services and discovery APIs are being targeted.
* Implement strong Identity and Access Management (IAM) policies, including multi-factor authentication (MFA) for all users, to prevent compromised credentials from being used for reconnaissance.
* Regularly audit IAM access keys and rotate them, especially if `aws.cloudtrail.user_identity.access_key_id` is identified in suspicious activity.

---
title: AWS Discovery API Calls via CLI from a Single Resource
slug: 2024-11-aws-discovery-api-calls
description: This rule detects when a single AWS identity executes more than five unique discovery-related API calls (Describe*, List*, Get*, or Generate*) within a 10-second window using the AWS CLI, potentially indicating reconnaissance activity following credential compromise or compromised EC2 instance access.
date: "2026-05-01T19:43:38Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - cloudtrail
  - discovery
vendors:
  - AWS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_multiple_discovery_api_calls_via_cli.toml
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
  - https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.pdf
  - https://github.com/aws-samples/aws-incident-response-playbooks/tree/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks
  - https://github.com/aws-samples/aws-customer-playbook-framework
rules:
  - title: AWS Discovery API Calls via CLI from Single Identity
    description: Detects a single AWS identity executing multiple discovery API calls via the AWS CLI within a short timeframe.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087.004
      - T1526
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Discovery API Calls from Unusual Source IP
    description: Detects a single AWS identity executing multiple discovery API calls from source IP outside of organization's usual AWS usage
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087.004
      - T1526
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection rule identifies suspicious AWS reconnaissance activity originating from the AWS CLI. It triggers when a single AWS identity (IAM user, role, or service principal) makes more than five unique discovery-related API calls (such as `Describe*`, `List*`, `Get*`, or `Generate*`) within a 10-second window. The rule is designed to detect adversaries attempting to map out an AWS environment after gaining unauthorized access through compromised credentials or a compromised EC2 instance. The tool focuses on API calls related to key AWS services like EC2, IAM, S3, and KMS. This rule helps defenders identify and respond to early-stage reconnaissance activity, preventing further exploitation or data exfiltration. The rule excludes activity from AWS service accounts and the AWS Management Console, and it requires a minimum stack version of 9.2.0 with AWS integration version 4.6.0.

## Attack Chain

1.  **Initial Access:** An attacker gains access to an AWS environment, potentially through compromised credentials or by compromising an EC2 instance.
2.  **Credential Usage:** The attacker leverages the AWS CLI to interact with the AWS environment using the compromised credentials.
3.  **Reconnaissance:** The attacker initiates a series of discovery API calls to gather information about the AWS infrastructure. This includes using `Describe*`, `List*`, `Get*`, and `Generate*` commands.
4.  **Resource Enumeration:** The attacker enumerates various AWS resources, including EC2 instances, IAM roles, S3 buckets, and KMS keys, by querying their respective APIs.
5.  **Target Identification:** The attacker analyzes the gathered information to identify potential targets for further exploitation, such as vulnerable EC2 instances or misconfigured S3 buckets.
6.  **Privilege Escalation (Optional):** If the compromised credentials have limited permissions, the attacker might attempt to escalate privileges to gain broader access to the AWS environment.
7.  **Lateral Movement (Optional):** The attacker might attempt to move laterally to other AWS accounts or services to expand their reach and impact.
8.  **Data Exfiltration/Impact:** Based on the attacker's goals, they may attempt to exfiltrate sensitive data or cause disruption by modifying or deleting resources.

## Impact

Successful exploitation could lead to unauthorized access to sensitive data, such as customer information, intellectual property, or financial records. The attacker could also disrupt business operations by modifying or deleting critical resources. Identifying and responding to such activity in a timely manner can help prevent significant damage and maintain the security and integrity of the AWS environment.

## Recommendation

*   Deploy the following Sigma rule to your SIEM and tune for your environment to detect the described reconnaissance activity.
*   Enable AWS CloudTrail logging for all AWS regions and accounts in your organization to ensure the required logs are available for detection.
*   Investigate any alerts generated by the Sigma rule, focusing on identifying the affected AWS identity, the source IP address, and the specific API calls made (as captured by the Sigma rule).
*   If suspicious activity is confirmed, follow AWS's incident-handling guidance, including disabling or rotating the access key used and restricting outbound connectivity from the source (reference the AWS Security Incident Response Guide).

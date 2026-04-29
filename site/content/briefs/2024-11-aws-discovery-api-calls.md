---
title: AWS Discovery API Calls via CLI from a Single Resource
slug: 2024-11-aws-discovery-api-calls
description: Detection of multiple AWS discovery API calls made via the AWS CLI from a single resource within a 10-second window, potentially indicating reconnaissance attempts by an attacker with compromised credentials or a compromised instance.
date: "2026-04-03T18:54:25Z"
type: coverage
types:
  - coverage
severities:
  - low
tags:
  - cloud
  - aws
  - discovery
  - reconnaissance
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
  - https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.pdf
rules:
  - title: AWS Multiple Discovery API Calls via CLI
    description: Detects multiple AWS discovery API calls via CLI from a single identity within a short timeframe.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Discovery API Calls from Unusual Source IP
    description: Detects AWS discovery API calls originating from outside known corporate IP ranges, potentially indicating compromised credentials or external reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies instances where a single AWS resource executes more than five unique discovery-related API calls (Describe*, List*, Get*, or Generate*) within a 10-second window using the AWS CLI. This behavior can indicate an adversary attempting to discover the AWS infrastructure using compromised credentials or a compromised instance. Such reconnaissance is often an early phase of compromise after credential exposure or access to a compromised EC2 instance. The detection excludes service accounts and console-based activity to reduce false positives and focuses on API calls from IAM, EC2, S3, RDS, Lambda, DynamoDB, KMS, CloudFront, Elastic Load Balancing, CloudTrail, STS, SES, and Organizations services. This activity matters because it is often a precursor to lateral movement, privilege escalation, and data exfiltration. The rule was introduced in Elastic Stack version 9.2.0 and AWS integration version 4.6.0.

## Attack Chain

1. An attacker gains unauthorized access to an AWS environment, either through compromised credentials or a compromised EC2 instance.
2. The attacker uses the AWS CLI to interact with AWS resources.
3. The attacker begins enumerating AWS resources by executing a series of discovery API calls, such as `DescribeInstances`, `ListRoles`, `ListBuckets`, and `ListKeys`.
4. These API calls target various AWS services, including EC2, IAM, S3, RDS, Lambda, DynamoDB, KMS, CloudFront, Elastic Load Balancing, CloudTrail, STS, SES, and Organizations.
5. The attacker scripts the API calls to rapidly gather information about the AWS environment.
6. The attacker analyzes the gathered information to identify potential targets for further exploitation or to gain a better understanding of the target's infrastructure.
7. Based on the discovered information, the attacker may attempt to move laterally within the environment, escalate privileges, or exfiltrate sensitive data.
8. The attacker achieves their final objective, such as data theft, service disruption, or infrastructure compromise.

## Impact

A successful reconnaissance phase can enable attackers to map out the target's AWS infrastructure, identify vulnerable systems and services, and plan further attacks. This can lead to data breaches, service disruptions, and significant financial losses. While this specific detection is tuned to a low severity, if successful, the subsequent stages can have a critical impact on the confidentiality, integrity, and availability of AWS resources and data. Organizations across all sectors are potentially at risk, especially those with complex AWS environments.

## Recommendation

*   Deploy the Sigma rule "AWS Multiple Discovery API Calls via CLI" to your SIEM and tune the threshold (currently > 5) for your environment.
*   Investigate alerts triggered by the Sigma rule, focusing on the user identity ARN (`aws.cloudtrail.user_identity.arn`) and source IP (`source.ip`) to determine the legitimacy of the activity.
*   Monitor CloudTrail logs for follow-on actions such as `GetCallerIdentity`, `AssumeRole`, `CreateAccessKey`, or data access (`GetObject`, `CopySnapshot`) associated with the same user identity ARN as mentioned in the overview.
*   Restrict outbound connectivity for instances identified by the detection to limit potential data exfiltration.

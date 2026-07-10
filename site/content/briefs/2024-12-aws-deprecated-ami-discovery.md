---
title: AWS EC2 Deprecated AMI Discovery
slug: 2024-12-aws-deprecated-ami-discovery
description: A user querying for deprecated Amazon Machine Images (AMIs) in AWS via the DescribeImages API call may indicate an adversary looking for outdated and potentially vulnerable AMIs for exploitation.
date: "2024-12-24T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - ec2
  - discovery
vendors:
  - AWS
products:
  - Amazon EC2
  - Amazon Machine Image
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-deprecate.html
rules:
  - title: AWS EC2 Deprecated AMI Discovery
    description: Detects when a user queries AWS for deprecated Amazon Machine Images (AMIs), which may indicate reconnaissance for vulnerable systems.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 Deprecated AMI Discovery - Source IP Analysis
    description: Detects when a user from a suspicious IP queries AWS for deprecated Amazon Machine Images (AMIs).
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

This rule detects when a user queries AWS for deprecated Amazon Machine Images (AMIs) using the `DescribeImages` API call. While querying for deprecated AMIs is not inherently malicious, it may indicate an adversary searching for outdated AMIs that may be vulnerable to exploitation. This behavior may stem from a misconfiguration or a legitimate use case, such as security assessments or legacy system maintenance. The rule focuses on identifying `DescribeImages` API calls with the `includeDeprecated` parameter set to "true," which signifies an explicit request for deprecated AMIs. This activity warrants investigation to determine the intent behind the query and assess potential security risks within the AWS environment.

## Attack Chain

1.  **Initial Access:** The attacker gains access to an AWS account through compromised credentials or a misconfigured IAM role.
2.  **Reconnaissance:** The attacker uses the AWS CLI or SDK to query for deprecated AMIs via the `DescribeImages` API call, setting the `includeDeprecated` parameter to "true."
3.  **Discovery:** The attacker analyzes the results of the `DescribeImages` API call to identify deprecated AMIs that may be vulnerable to exploitation.
4.  **Vulnerability Assessment:** The attacker researches the identified deprecated AMIs for known vulnerabilities and exploits.
5.  **Resource Provisioning:** The attacker attempts to launch an EC2 instance using a deprecated AMI, potentially bypassing security controls due to the AMI's age.
6.  **Privilege Escalation/Lateral Movement:** If the deprecated AMI contains vulnerable software, the attacker exploits it to gain elevated privileges or move laterally within the AWS environment.
7.  **Data Exfiltration/Impact:** The attacker uses the compromised EC2 instance to exfiltrate sensitive data or cause disruption to AWS services.

## Impact

A successful attack leveraging deprecated AMIs can lead to the compromise of EC2 instances, data breaches, and service disruptions. While this event by itself is low severity, it can act as a part of a larger attack and indicate the early stages of cloud reconnaissance. The impact of exploiting vulnerable AMIs includes data exfiltration, service downtime, and unauthorized access to other AWS resources.

## Recommendation

*   Deploy the Sigma rule `AWS EC2 Deprecated AMI Discovery` to your SIEM to detect queries for deprecated AMIs and tune for your environment.
*   Review the source IP address (`source.ip`) of the request to identify potentially suspicious origins as per the `AWS EC2 Deprecated AMI Discovery` rule.
*   Restrict IAM permissions to prevent unauthorized access to deprecated AMIs as mentioned in the investigation steps.
*   Enable alerts for future queries involving deprecated AMIs or other unusual API activity within CloudTrail logs as mentioned in the remediation steps.

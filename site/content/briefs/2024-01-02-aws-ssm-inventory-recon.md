---
title: AWS SSM Inventory Reconnaissance by Rare User
slug: 2024-01-02-aws-ssm-inventory-recon
description: Detection of a rare user or role accessing AWS Systems Manager (SSM) inventory APIs or running the AWS-GatherSoftwareInventory job, potentially indicating reconnaissance activity by threat actors seeking information about managed EC2 instances.
date: "2024-01-02T12:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Scattered Spider (LUCR-3)
tags:
  - aws
  - ssm
  - inventory
  - reconnaissance
  - cloudtrail
vendors:
  - AWS
products:
  - AWS Systems Manager
  - AWS EC2
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1518
    technique_name: Software Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1538
    technique_name: Cloud Service Dashboard
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
  - https://www.cisa.gov/sites/default/files/2023-11/aa23-320a_scattered_spider_0.pdf
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-inventory.html
rules:
  - title: AWS SSM Inventory Reconnaissance by Rare User
    description: Detects rare access to AWS SSM inventory APIs, potentially indicating reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1518
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: AWS SSM Gather Software Inventory Job Execution
    description: Detects execution of the AWS-GatherSoftwareInventory job via CreateAssociation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1518
      - T1580
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the initial use of AWS Systems Manager (SSM) inventory APIs by a specific user or role, which is uncommon behavior and may indicate reconnaissance. The AWS SSM Inventory service provides detailed information about managed EC2 instances, including installed software, patch compliance status, and command execution history. Threat actors, such as Scattered Spider (LUCR-3), may abuse these APIs to gather information about target systems within an AWS environment for lateral movement or other malicious purposes. The rule focuses on detecting the first-time use of specific SSM inventory APIs (GetInventory, GetInventorySchema, ListInventoryEntries, DescribeInstancePatches, ListCommands) or the execution of the AWS-GatherSoftwareInventory job by a user, as such actions are more typical of automation systems rather than interactive human users.

## Attack Chain

1.  Initial Access: An attacker gains access to an AWS account through compromised credentials or an exposed IAM role.
2.  Credential Harvesting: The attacker enumerates existing IAM roles and policies to identify those with permissions to interact with SSM.
3.  SSM Enumeration: The attacker uses the `sts:GetCallerIdentity` API call to validate permissions and identify the current AWS account.
4.  Inventory Discovery: The attacker leverages SSM inventory APIs, such as `ssm:GetInventory`, `ssm:GetInventorySchema`, and `ssm:ListInventoryEntries`, to gather information about EC2 instances, including installed software and patch levels.
5.  Patch Status Check: The attacker uses `ssm:DescribeInstancePatches` to identify vulnerable or unpatched systems.
6.  Command History Check: The attacker uses `ssm:ListCommands` to gather information about past commands executed on the instances.
7.  Software Inventory Job Execution: Alternatively, the attacker triggers the `AWS-GatherSoftwareInventory` job using `ssm:CreateAssociation` to collect a comprehensive software inventory.
8.  Lateral Movement: Based on the gathered inventory, the attacker identifies vulnerable systems or misconfigurations and attempts lateral movement within the AWS environment.

## Impact

Successful reconnaissance using AWS SSM Inventory APIs allows attackers to map out the target environment, identify vulnerable systems, and plan further attacks, such as lateral movement or data exfiltration. This reconnaissance can lead to full compromise of EC2 instances and sensitive data within the AWS environment. Scattered Spider and similar groups often use this information to identify high-value targets and vulnerabilities for exploitation.

## Recommendation

*   Deploy the Sigma rule "AWS SSM Inventory Reconnaissance by Rare User" to your SIEM to detect anomalous SSM inventory API usage (rule).
*   Investigate any alerts triggered by the Sigma rule, focusing on the source IP address, user agent, and the specific API calls made (rule).
*   Review IAM permissions to ensure that users and roles only have the necessary permissions to access SSM inventory data (IAM).
*   Implement enhanced monitoring for users or roles identified as performing suspicious SSM activity (monitoring).
*   Correlate SSM API activity with other AWS CloudTrail events, such as `StartSession` or `SendCommand`, to identify broader attack patterns (CloudTrail).
*   Use the provided references to understand Scattered Spider's TTPs and AWS security best practices (references).

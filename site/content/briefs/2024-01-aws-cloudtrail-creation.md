---
title: AWS CloudTrail Trail Creation Detected
slug: 2024-01-aws-cloudtrail-creation
description: Detection of new AWS CloudTrail trail creation, potentially indicating malicious activity such as subverting monitoring objectives or capturing sensitive data by adversaries.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - cloudtrail
  - collection
  - defense_evasion
vendors:
  - AWS
products:
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_CreateTrail.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/create-trail.html
rules:
  - title: AWS CloudTrail Log Created
    description: Detects creation of a new AWS CloudTrail trail via CreateTrail API. Adversaries can create trails that write to attacker-controlled destinations, limit regions, or otherwise subvert monitoring objectives.
    platform: sigma
    severity: low
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1530
      - T1562
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudTrail Modified Trail
    description: Detects modification of an existing AWS CloudTrail trail via UpdateTrail API. Adversaries can modify trails to write to attacker-controlled destinations, limit regions, or otherwise subvert monitoring objectives.
    platform: sigma
    severity: low
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1530
      - T1562
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the creation of new AWS CloudTrail trails via the `CreateTrail` API call. While legitimate trail creation occurs during onboarding or audit improvements, adversaries may create trails to write logs to attacker-controlled destinations, limit the scope of regions monitored, or otherwise subvert existing monitoring objectives. Detecting unauthorized trail creation is critical because adversaries can use this technique to capture sensitive data, cover their tracks, or disable logging altogether. Organizations should validate new trails for destination ownership, encryption, multi-region coverage, and organizational scope upon creation. This activity directly impacts an organization's ability to detect and respond to security incidents within their AWS environment.

## Attack Chain

1.  The adversary gains initial access to an AWS account through compromised credentials or other means.
2.  The adversary enumerates existing CloudTrail configurations using `DescribeTrails` to understand the current logging setup.
3.  The adversary identifies potential gaps in the existing logging configuration, such as missing regions or inadequate S3 bucket permissions.
4.  The adversary creates a new CloudTrail trail using the `CreateTrail` API, configured to send logs to an attacker-controlled S3 bucket or CloudWatch Logs Log Group.
5.  The adversary may configure the new trail to exclude specific regions or services to avoid detection of their activities.
6.  The adversary may use `PutEventSelectors` to configure the newly created trail to log specific events of interest, potentially capturing sensitive data.
7.  The adversary activates the new trail using `StartLogging`.
8.  The adversary proceeds with their malicious activities, knowing that their actions may not be fully logged or monitored by the organization's security team.

## Impact

Successful exploitation allows adversaries to capture sensitive data logged by CloudTrail, such as API keys, credentials, and configuration details. This can lead to further compromise of the AWS environment and potentially exfiltration of data. In addition, adversaries can disable or modify existing CloudTrail logs, hindering incident response and forensic investigations. The impact is reduced visibility into malicious activity, enabling attackers to operate undetected within the AWS environment.

## Recommendation

*   Deploy the Sigma rule "AWS CloudTrail Log Created" to your SIEM to detect suspicious trail creation activities.
*   Investigate any `CreateTrail` events detected by the Sigma rule, focusing on unfamiliar user identities, user agents, and source IPs.
*   Validate the configuration of newly created trails, verifying that the `S3BucketName` and `CloudWatchLogsLogGroupArn` belong to your organization, `IsMultiRegionTrail` is set to `true`, and `KmsKeyId` is an approved CMK, as detailed in the rule's documentation.
*   Restrict `cloudtrail:CreateTrail` permissions to only authorized administrators using IAM policies to prevent unauthorized trail creation.
*   Use AWS Config or Security Hub to enforce multi-region logging, global event inclusion, and validated log destinations.

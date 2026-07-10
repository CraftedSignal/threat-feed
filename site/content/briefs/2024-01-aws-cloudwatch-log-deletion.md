---
title: AWS CloudWatch Log Group Deletion for Defense Evasion
slug: 2024-01-aws-cloudwatch-log-deletion
description: The deletion of AWS CloudWatch log groups, detected via CloudTrail logs, indicates a potential defense evasion attempt by adversaries aiming to remove audit trails and hinder incident response.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - defense-evasion
vendors:
  - AWS
products:
  - AWS CloudWatch
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/aws_defense_evasion_delete_cloudwatch_log_group.yml
rules:
  - title: AWS CloudWatch Log Group Deletion
    description: Detects the deletion of CloudWatch log groups in AWS via CloudTrail logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudWatch Log Group Deletion by Console
    description: Detects the deletion of CloudWatch log groups in AWS via AWS Management Console.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

Attackers may delete CloudWatch log groups to remove evidence of their malicious activities within an AWS environment. This action is detected by monitoring CloudTrail logs for `DeleteLogGroup` events. The deletion of log groups, especially when performed outside of normal administrative tasks, can be a strong indicator of an attacker attempting to evade detection and hide their tracks. The targeting scope includes organizations leveraging AWS CloudWatch for logging and monitoring. This behavior can significantly impede incident response efforts, making it difficult to reconstruct attack timelines and identify compromised resources. Detecting and responding to such events is critical for maintaining security visibility and control within the AWS environment.

## Attack Chain

1.  An attacker gains unauthorized access to an AWS account, potentially through compromised credentials or exploiting a vulnerability in an exposed service.
2.  The attacker enumerates existing CloudWatch log groups to identify those containing valuable audit or security-related logs.
3.  The attacker authenticates to the AWS API using stolen or generated credentials.
4.  The attacker issues a `DeleteLogGroup` API call via the AWS CLI, SDK, or API directly, targeting specific log groups. The request is crafted to successfully delete the log group.
5.  CloudTrail logs the `DeleteLogGroup` event, recording details such as the user, timestamp, and target log group.
6.  The attacker may repeat the process to delete multiple log groups, systematically removing traces of their activity.
7.  The successful deletion of the CloudWatch log group removes logs crucial for forensic analysis and incident response.
8.  The attacker continues their malicious activities, now with a reduced risk of detection due to the absence of logs.

## Impact

Successful deletion of CloudWatch log groups allows attackers to operate with significantly reduced visibility. This can lead to delayed incident detection, increased dwell time, and greater potential for data exfiltration or system compromise. Organizations relying on CloudWatch logs for security monitoring and compliance are particularly vulnerable. The impact includes hindering forensic investigations, impeding incident response efforts, and potentially violating compliance requirements.

## Recommendation

*   Deploy the Sigma rule `AWS CloudWatch Log Group Deletion` to detect attempts to delete CloudWatch log groups based on CloudTrail events.
*   Investigate any detected `DeleteLogGroup` events, especially those originating from unusual IP addresses or user accounts.
*   Implement strict IAM policies to restrict the ability to delete CloudWatch log groups to authorized personnel only.
*   Monitor CloudTrail logs for unauthorized API calls and suspicious activity related to CloudWatch.
*   Enable multi-factor authentication (MFA) for all AWS accounts to reduce the risk of credential compromise.
*   Review and enforce least privilege principles for all IAM roles and users.

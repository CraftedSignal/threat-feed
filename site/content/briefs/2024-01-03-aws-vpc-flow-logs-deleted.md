---
title: AWS VPC Flow Logs Deletion for Defense Evasion
slug: 2024-01-03-aws-vpc-flow-logs-deleted
description: An adversary may delete VPC Flow Logs in AWS EC2 by calling the DeleteFlowLogs API to evade detection and hinder forensic investigations.
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
  - vpc
  - flow-logs
vendors:
  - Amazon
products:
  - Elastic Compute Cloud (EC2)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-flow-logs.html
  - https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/aws/defense_evasion_ec2_flow_log_deletion
rules:
  - title: AWS VPC Flow Logs Deleted
    description: Detects the deletion of one or more VPC Flow Logs in AWS EC2 through the DeleteFlowLogs API call.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1562.008
    data_sources:
      - aws
      - cloudtrail
  - title: AWS VPC Flow Logs Deletion Attempt Failed
    description: Detects a failed attempt to delete VPC Flow Logs in AWS EC2.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1562.008
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

An adversary with sufficient privileges within an AWS environment may attempt to delete VPC Flow Logs. These logs are crucial for monitoring network traffic within a VPC, and their removal can significantly impede incident response and forensic investigations. The deletion is accomplished by making a `DeleteFlowLogs` API call. This action is often taken to remove evidence of malicious activity, such as lateral movement, command and control communication, or data exfiltration. The impact of this activity can be severe, potentially allowing attackers to operate undetected for extended periods.

## Attack Chain

1.  The attacker gains initial access to the AWS environment through compromised credentials or an exploited vulnerability (not detailed in source).
2.  The attacker escalates privileges within the AWS environment to gain the necessary permissions to delete VPC Flow Logs (not detailed in source).
3.  The attacker uses the AWS CLI or AWS Management Console to execute the `DeleteFlowLogs` API call.
4.  The attacker identifies the specific Flow Log IDs that need to be deleted.
5.  The attacker authenticates to the AWS API using stolen or generated credentials.
6.  The `DeleteFlowLogs` API call is made, specifying the Flow Log IDs to be deleted.
7.  AWS processes the request and deletes the specified VPC Flow Logs.
8.  The attacker verifies the deletion of the Flow Logs to ensure that their actions are no longer being logged.

## Impact

Successful deletion of VPC Flow Logs prevents security teams from detecting malicious activity within the AWS environment. Without these logs, it becomes significantly more difficult to investigate security incidents, track attacker movements, and understand the scope of a compromise. This can lead to delayed incident response, increased dwell time for attackers, and greater overall damage. The absence of flow logs severely limits network visibility, hindering any attempt to reconstruct events or identify compromised assets.

## Recommendation

*   Implement the Sigma rule "AWS VPC Flow Logs Deleted" to detect instances of `DeleteFlowLogs` API calls (reference: rules section).
*   Monitor CloudTrail logs for `DeleteFlowLogs` events and investigate any unexpected occurrences (reference: logsource).
*   Enforce the principle of least privilege to restrict IAM users and roles from having the `ec2:DeleteFlowLogs` permission unless absolutely necessary.
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with administrative privileges.
*   Regularly review and audit IAM policies to ensure that permissions are appropriately scoped and not overly permissive.

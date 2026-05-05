---
title: AWS CloudWatch Log Group Deletion for Defense Evasion
slug: 2024-01-aws-cloudwatch-log-deletion
description: Detection of AWS CloudWatch log group deletions via CloudTrail logs, excluding console-based actions, indicating potential defense evasion by attackers attempting to hide their tracks.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudwatch
  - defense-evasion
vendors:
  - Splunk
  - Amazon
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CloudWatch
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: AWS CloudWatch Log Group Deletion
    description: Detects the deletion of CloudWatch log groups in AWS, excluding console-based actions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudWatch Log Group Deletion via API
    description: Detects the deletion of CloudWatch log groups in AWS via API calls.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

Attackers may delete CloudWatch log groups to remove evidence of their activities within an AWS environment. This action, identified through `DeleteLogGroup` events in CloudTrail, allows them to evade detection and forensic analysis. The activity is detected by monitoring CloudTrail logs for successful log group deletions, excluding those initiated from the AWS console. This behavior is significant because it directly undermines the logging and monitoring infrastructure that defenders rely on for incident response and threat hunting. The original Splunk ES-CU analytic was published in 2026-05-05, but the underlying technique is still relevant.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account.
2. The attacker enumerates existing CloudWatch log groups using AWS CLI or API calls to identify potential targets for deletion.
3. The attacker uses compromised credentials or a compromised IAM role to execute the `DeleteLogGroup` API call via AWS CLI, SDK, or API.
4. CloudTrail logs the `DeleteLogGroup` event with `eventSource = logs.amazonaws.com` and a successful `errorCode`.
5. The attacker may repeat this process for multiple log groups to eliminate a broader range of forensic data.
6. The CloudWatch log group is permanently deleted, removing any logs it contained from the defender's visibility.
7. The attacker continues their malicious activities, now with reduced risk of detection due to the absence of relevant logs.

## Impact

Successful deletion of CloudWatch log groups allows attackers to operate with significantly reduced visibility. This can lead to delayed incident detection and response, increased dwell time, and greater potential for data exfiltration or system compromise. The deletion of logs hampers forensic investigations, making it difficult to determine the scope and impact of the attack. In environments with strict compliance requirements, such as those governed by HIPAA or PCI DSS, this can lead to significant penalties and reputational damage.

## Recommendation

*   Deploy the Sigma rule "AWS CloudWatch Log Group Deletion" to your SIEM to detect unauthorized log group deletions using `eventName = DeleteLogGroup` and `eventSource = logs.amazonaws.com`.
*   Enable AWS CloudTrail logging to capture `DeleteLogGroup` events within your AWS environment.
*   Investigate any detected `DeleteLogGroup` events, especially those not initiated from the AWS console (`userAgent !=console.amazonaws.com`), as potential indicators of malicious activity.
*   Implement strict IAM policies to limit the ability to delete CloudWatch log groups to only authorized personnel.

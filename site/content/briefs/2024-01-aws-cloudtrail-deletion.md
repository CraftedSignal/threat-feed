---
title: AWS CloudTrail Log Deletion for Defense Evasion
slug: 2024-01-aws-cloudtrail-deletion
description: An adversary may delete AWS CloudTrail logs to evade detection and operate stealthily within a compromised environment, using the `DeleteTrail` event while excluding actions from the AWS console.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - defense-evasion
vendors:
  - Amazon
  - Splunk
products:
  - AWS CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: AWS CloudTrail DeleteTrail Event
    description: Detects deletion of AWS CloudTrail logs by identifying DeleteTrail events not originating from the AWS console.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudTrail DeleteTrail Event by User
    description: Detects deletion of AWS CloudTrail logs by identifying DeleteTrail events and the associated user.
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

This brief focuses on the detection of AWS CloudTrail log deletion, a tactic used by adversaries to evade detection within compromised AWS environments. The detection identifies `DeleteTrail` events within CloudTrail logs, specifically excluding those originating from the AWS console. This activity is crucial for defenders because successful deletion of CloudTrail logs allows attackers to cover their tracks, making it significantly more difficult to trace malicious activities. This can lead to prolonged unauthorized access, further exploitation, and delayed incident response. The detection logic looks for the `DeleteTrail` event name and filters out events where the user agent is the AWS console.

## Attack Chain

1.  The attacker gains unauthorized access to an AWS account with sufficient privileges.
2.  The attacker identifies that CloudTrail is enabled and logging activities.
3.  The attacker attempts to disable or delete the CloudTrail trail to remove evidence of their actions, using the `DeleteTrail` API call.
4.  The attacker crafts the `DeleteTrail` request, ensuring it does not originate from the AWS Management Console to avoid detection based on user agent.
5.  The `DeleteTrail` API call is executed, successfully deleting the CloudTrail log.
6.  CloudTrail logs, which would normally record the attacker's subsequent actions, are no longer available for analysis.
7.  The attacker proceeds with their malicious objectives, such as data exfiltration, resource hijacking, or deployment of malware, without leaving a readily accessible audit trail.
8.  The attacker successfully covers their tracks, hindering incident responders' ability to investigate and remediate the breach effectively.

## Impact

Successful deletion of CloudTrail logs severely impairs an organization's ability to detect and respond to security incidents within their AWS environment. This can lead to a significant delay in incident response, allowing attackers to maintain persistent access and further compromise systems. The absence of logs hinders forensic investigations, making it difficult to determine the scope and impact of the breach. This can result in financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the Sigma rule provided in this brief to your SIEM and tune it for your specific environment to detect `DeleteTrail` events.
*   Investigate any detected `DeleteTrail` events that do not originate from the AWS console, as this may indicate malicious activity.
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with administrative privileges, to reduce the risk of unauthorized access.
*   Monitor CloudTrail configuration changes using AWS Config to detect and alert on unauthorized modifications to CloudTrail settings.
*   Enable and configure AWS CloudTrail log file validation to detect any tampering with CloudTrail log files.

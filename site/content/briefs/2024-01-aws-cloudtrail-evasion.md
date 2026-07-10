---
title: AWS CloudTrail Logging Modification for Defense Evasion
slug: 2024-01-aws-cloudtrail-evasion
description: Attackers modify AWS CloudTrail logging configurations to evade detection by disabling or altering logging, hindering security visibility and potentially allowing further malicious activities to go unnoticed.
date: "2024-01-03T12:00:00Z"
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
  - AWS
products:
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: Detect AWS CloudTrail UpdateTrail Outside Console
    description: Detects UpdateTrail events in AWS CloudTrail logs where the user agent is not the AWS console, indicating potential defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS CloudTrail Trail Stopped
    description: Detects CloudTrail events where a trail is stopped, which could indicate an attempt to evade logging.
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

Attackers may attempt to modify or disable AWS CloudTrail logging to evade detection and hide their malicious activities within an AWS environment. This technique involves altering CloudTrail configurations, such as stopping log collection, modifying log storage locations, or changing the log file validation settings. The detection focuses on identifying unauthorized or suspicious modifications to CloudTrail settings, specifically `UpdateTrail` events, initiated from outside the AWS console. This activity is critical because CloudTrail provides essential logs for monitoring and auditing AWS account activities, and any tampering can significantly impair security monitoring and incident response capabilities. The scope of this evasion can span across an entire AWS account or specific regions, depending on the permissions and access of the attacker.

## Attack Chain

1.  The attacker gains initial access to the AWS environment, possibly through compromised credentials or exploiting a vulnerable service.
2.  The attacker enumerates existing CloudTrail trails to identify the targets for modification using AWS CLI or API calls.
3.  The attacker invokes the `UpdateTrail` API call to modify the CloudTrail configuration.
4.  The `UpdateTrail` request specifies changes to the trail, such as disabling logging by setting `IsLogging` to `false`.
5.  The attacker may also modify the S3 bucket associated with the trail to redirect logs to a different location they control.
6.  The attacker validates that the changes to the CloudTrail configuration have been successfully applied.
7.  With logging disabled or altered, the attacker proceeds with their objectives, knowing their actions are less likely to be logged and detected.
8.  The final objective may include data exfiltration, deployment of malicious resources, or further lateral movement within the AWS environment.

## Impact

Successful modification of CloudTrail settings results in a significant loss of visibility into activities within the AWS environment. This can allow attackers to operate undetected, potentially leading to data breaches, unauthorized resource access, or deployment of persistent malware. The impact extends to hindering incident response efforts, as critical log data required for investigation is either unavailable or tampered with. Depending on the scope of the compromise, this could affect entire business units or critical infrastructure managed within the AWS account.

## Recommendation

*   Deploy the Sigma rule `Detect AWS CloudTrail UpdateTrail Outside Console` to identify attempts to modify CloudTrail settings from unauthorized sources (logsource: `aws:cloudtrail`, eventName: `UpdateTrail`).
*   Monitor `UpdateTrail` events in CloudTrail logs (data_source: `AWS CloudTrail UpdateTrail`) and investigate any modifications performed by users or roles that are not explicitly authorized to manage CloudTrail configurations.
*   Enable multi-factor authentication (MFA) for all IAM users and roles with permissions to modify CloudTrail configurations to prevent unauthorized access (reference: [https://attack.mitre.org/techniques/T1562/008/](https://attack.mitre.org/techniques/T1562/008/)).
*   Implement strong IAM policies that restrict the ability to modify or delete CloudTrail trails to a limited set of highly privileged accounts (logsource: `aws:cloudtrail`).

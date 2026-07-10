---
title: AWS CloudTrail UpdateTrail Defense Evasion
slug: 2024-01-aws-cloudtrail-update
description: An attacker modifies AWS CloudTrail configurations, specifically using the UpdateTrail API, to evade detection by impairing logging of their activities across multiple regions.
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
  - cloud
vendors:
  - AWS
products:
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/asl_aws_defense_evasion_update_cloudtrail.yml
rules:
  - title: Detect AWS CloudTrail UpdateTrail API Call
    description: Detects calls to the AWS CloudTrail UpdateTrail API, potentially indicating an attempt to disable or modify logging.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS CloudTrail UpdateTrail API Call with Modified Multi-Region Logging
    description: Detects calls to the AWS CloudTrail UpdateTrail API that disable or modify multi-region logging.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This analytic detects the use of the `UpdateTrail` API call in AWS CloudTrail logs, which is a common technique used by attackers to evade detection. By modifying CloudTrail settings, such as disabling multi-region logging or changing the destination bucket, adversaries can significantly reduce the visibility of their malicious activities. This activity is critical to monitor, as successful evasion can allow attackers to operate undetected within an AWS environment, leading to delayed incident response and potential data breaches. The detection focuses on identifying modifications to CloudTrail configurations that deviate from established security best practices, potentially indicating malicious intent. The security content was published on 2026-04-17 and aims to detect threat actors modifying CloudTrail configurations.

## Attack Chain

1.  The attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a vulnerability in an application running within the environment.
2.  The attacker enumerates existing CloudTrail configurations to identify potential targets for modification.
3.  The attacker calls the `UpdateTrail` API to modify CloudTrail settings. This may include disabling multi-region logging, changing the destination bucket, or altering encryption settings.
4.  The attacker modifies the CloudTrail configuration to log only single region activity, evading logging in other regions where they plan to operate.
5.  The attacker performs malicious activities within the AWS environment, such as deploying unauthorized resources, exfiltrating data, or compromising other systems.
6.  Because of the modified CloudTrail configuration, these malicious activities are not fully logged or are logged to a location inaccessible to security monitoring tools.
7.  The attacker attempts to delete or further obfuscate any remaining logs.
8.  The attacker achieves their final objective, such as data theft, system compromise, or service disruption, with reduced risk of detection.

## Impact

Successful evasion of CloudTrail logging can have significant consequences, including delayed detection of breaches, incomplete forensic investigations, and increased dwell time for attackers. This can lead to substantial data loss, financial damage, and reputational harm. Depending on the scope of the compromise, multiple AWS accounts and regions could be affected.

## Recommendation

*   Deploy the Sigma rule `Detect AWS CloudTrail UpdateTrail API Call` to your SIEM and tune for your environment.
*   Investigate any `UpdateTrail` events identified by the Sigma rule, focusing on changes to multi-region logging and destination buckets.
*   Monitor AWS CloudTrail logs for unusual API activity from accounts with administrative privileges.
*   Implement strong identity and access management (IAM) policies to limit the ability of users and roles to modify CloudTrail configurations.
*   Enable AWS Config to track changes to CloudTrail configurations and trigger alerts on unauthorized modifications.
*   Review CloudTrail configurations regularly to ensure they align with security best practices and organizational policies.

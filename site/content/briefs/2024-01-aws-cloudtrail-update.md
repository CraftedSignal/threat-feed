---
title: AWS CloudTrail Update for Defense Evasion
slug: 2024-01-aws-cloudtrail-update
description: Attackers may attempt to evade detection by altering CloudTrail logging configurations, such as changing multi-regional logging to a single region, which impairs the logging of their activities and hinders incident response.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloudtrail
  - defense-evasion
  - cloud
vendors:
  - Amazon
  - Splunk
products:
  - CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Add-on for Amazon Web Services
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: Detect AWS CloudTrail UpdateTrail Event
    description: Detects UpdateTrail events in AWS CloudTrail, indicating potential attempts to modify logging configurations for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS CloudTrail UpdateTrail with Multi-Region Disabled
    description: Detects UpdateTrail events in AWS CloudTrail where multi-region logging is disabled, indicating potential defense evasion.
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

This detection focuses on identifying attempts to evade detection within AWS environments by monitoring `UpdateTrail` events in AWS CloudTrail logs. Attackers may modify CloudTrail settings with incorrect parameters, such as switching from multi-regional logging to single-region logging, to reduce the scope of logged activities. This tactic allows adversaries to operate undetected in compromised AWS environments, as their actions in other regions are not properly recorded. Detecting these configuration changes is critical for Security Operations Centers (SOCs) to maintain visibility and respond effectively to threats. The lack of comprehensive logging can significantly impede incident response and forensic investigations, allowing malicious activities to persist unnoticed.

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials or an exposed API key (T1078).
2.  The attacker authenticates to the AWS Management Console or uses the AWS CLI with the compromised credentials.
3.  The attacker issues an `UpdateTrail` API call to modify the CloudTrail configuration (T1562.008).
4.  The attacker disables multi-region logging, restricting log collection to a single AWS region.
5.  Alternatively, the attacker modifies the S3 bucket used for log storage, potentially directing logs to an attacker-controlled location.
6.  The attacker performs malicious activities within the AWS environment, knowing that these actions will not be comprehensively logged across all regions.
7.  These malicious activities could include lateral movement, data exfiltration, or resource compromise.
8.  The reduced logging scope hinders detection and response efforts, allowing the attacker to maintain persistence and achieve their objectives.

## Impact

Successful evasion of CloudTrail logging can lead to significant blind spots in security monitoring.  If an attacker successfully modifies CloudTrail settings, their subsequent actions within the AWS environment are less likely to be detected.  This can lead to prolonged dwell time, increased data exfiltration, and greater overall damage. Organizations relying on CloudTrail for compliance and security auditing may also face regulatory repercussions due to incomplete logging. The blast radius of a successful attack expands significantly when logging is impaired, affecting potentially all resources within the AWS environment.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune it for your specific AWS environment to detect unauthorized CloudTrail modifications.
*   Investigate any `UpdateTrail` events where the `actor.user.uid` is not a known administrator account (see Sigma rule below).
*   Monitor CloudTrail logs for changes to multi-region logging settings and S3 bucket destinations (see references to `api.operation=UpdateTrail` in the `search` field).
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with administrative privileges to mitigate credential compromise (T1110).
*   Regularly review and audit CloudTrail configurations to ensure they align with security best practices and organizational policies.

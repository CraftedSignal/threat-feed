---
title: AWS CloudTrail Logging Evasion via UpdateTrail
slug: 2024-01-aws-cloudtrail-evasion
description: Attackers modify AWS CloudTrail settings using UpdateTrail events to evade detection by disabling or limiting logging, as indicated by non-console user agents.
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
  - logging
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
  - title: AWS CloudTrail UpdateTrail Event from Non-Console User Agent
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
  - title: AWS CloudTrail UpdateTrail Event Success
    description: Detects successful UpdateTrail events in AWS CloudTrail logs.
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

The threat involves adversaries attempting to evade detection within AWS environments by modifying CloudTrail settings. This is achieved through the use of `UpdateTrail` events, specifically targeting configurations that can limit or disable logging capabilities. The activity is identified by analyzing CloudTrail logs for `UpdateTrail` events where the user agent is not the AWS console and the operation is successful. This behavior, if malicious, allows attackers to operate undetected within the compromised AWS account, leading to further compromise and data exfiltration. This attack is significant because CloudTrail provides critical visibility into AWS account activity, and disabling or modifying it can severely hamper incident response and forensic investigations.

## Attack Chain

1.  An attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a vulnerability in a web application.
2.  The attacker authenticates to the AWS environment using the compromised credentials.
3.  The attacker executes an `UpdateTrail` API call to modify the CloudTrail configuration.
4.  The `UpdateTrail` call is made with a user agent different from the AWS console to avoid detection based on typical administrative behavior.
5.  The attacker modifies the trail settings, such as disabling logging, changing the destination bucket, or altering the included event types.
6.  The successful `UpdateTrail` event is logged in CloudTrail, but the attacker's subsequent actions are not logged due to the altered configuration.
7.  The attacker performs malicious activities within the AWS environment, such as data exfiltration, resource deployment, or privilege escalation.
8.  The attacker attempts to remove or obfuscate remaining evidence of the `UpdateTrail` modification to further hinder detection.

## Impact

Successful modification of CloudTrail settings can lead to a significant loss of visibility into AWS account activity. Attackers can operate undetected, exfiltrate sensitive data, deploy malicious resources, and escalate privileges without being logged. The number of victims is dependent on the scope of access granted to the compromised AWS account. Organizations across all sectors are potentially at risk, with the impact ranging from data breaches and financial loss to reputational damage and regulatory penalties.

## Recommendation

*   Deploy the Sigma rule `AWS CloudTrail UpdateTrail Event from Non-Console User Agent` to detect suspicious modifications to CloudTrail settings.
*   Investigate any `UpdateTrail` events where the user agent is not the AWS console (as highlighted by the Sigma rule) to determine if the changes were authorized.
*   Monitor CloudTrail logs for any unusual activity, especially API calls from unfamiliar IP addresses (`network_connection` events).
*   Implement multi-factor authentication (MFA) to protect AWS accounts from credential compromise (related to initial access stage).
*   Enable and review AWS Config rules to detect and remediate non-compliant CloudTrail configurations (check for disabled logging, modified buckets, etc.).

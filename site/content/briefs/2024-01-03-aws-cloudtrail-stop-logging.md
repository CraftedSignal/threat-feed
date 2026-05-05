---
title: AWS CloudTrail Logging Stopped for Defense Evasion
slug: 2024-01-03-aws-cloudtrail-stop-logging
description: Detection of AWS CloudTrail StopLogging events indicates a potential defense evasion attempt by an attacker to operate stealthily within a compromised AWS environment and hinder incident response.
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
  - aws-account
vendors:
  - Splunk
  - Amazon
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: AWS CloudTrail StopLogging Detection
    description: Detects StopLogging events in AWS CloudTrail, excluding console-based actions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudTrail StopLogging by User Agent
    description: Detects StopLogging events based on specific user agent strings, potentially indicating malicious tools.
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

This alert focuses on detecting the `StopLogging` event within AWS CloudTrail, a critical indicator of potential defense evasion. Attackers often disable CloudTrail logging to conceal their malicious activities, making it difficult for security teams to detect and respond to breaches effectively. The detection specifically looks for successful `StopLogging` events (`errorCode = success`) originating from sources other than the AWS console (`userAgent!=console.amazonaws.com`). By identifying these instances, security teams can quickly investigate the reasons behind the logging stoppage, determine if it was authorized, and take appropriate action to prevent further unauthorized activities. This is especially critical for maintaining visibility and control over AWS environments, ensuring that malicious actions are not conducted without a trace.

## Attack Chain

1.  The attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a misconfiguration.
2.  The attacker assumes a role or escalates privileges to gain sufficient permissions to manage CloudTrail.
3.  The attacker identifies the active CloudTrail trails within the AWS environment.
4.  The attacker executes the `StopLogging` API call against the identified CloudTrail trail.
5.  CloudTrail logs the `StopLogging` event, recording the action, user, and source IP.
6.  The attacker proceeds with malicious activities, such as data exfiltration, resource manipulation, or deploying backdoors, without being logged by CloudTrail.
7.  The attacker attempts to remove or modify existing security controls and monitoring configurations.
8.  The attacker persists in the environment, potentially creating new identities or backdoors to maintain access.

## Impact

Successful disabling of CloudTrail logging can have severe consequences. It impairs incident response by removing the primary source of audit data. Without CloudTrail logs, security teams lose visibility into attacker activities, making it difficult to determine the scope and impact of the breach. Attackers can operate undetected, exfiltrate sensitive data, modify critical resources, and establish persistent backdoors. The impact can range from data breaches and financial losses to reputational damage and regulatory fines.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect instances of `StopLogging` events in AWS CloudTrail logs and tune for your environment.
*   Investigate any detected `StopLogging` events, focusing on the user (`user`), source IP (`src`), and reason for stopping logging.
*   Enable multi-factor authentication (MFA) for all AWS accounts to prevent credential compromise (TTP: TA0001).
*   Enforce the principle of least privilege to minimize the impact of compromised credentials (TTP: TA0004).
*   Regularly review and audit CloudTrail configurations to ensure logging is enabled and properly configured (TTP: TA0005).
*   Implement alerting for changes to CloudTrail configuration to detect unauthorized modifications (TTP: TA0005).

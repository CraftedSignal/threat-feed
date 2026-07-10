---
title: AWS CloudTrail Stop Logging Detection
slug: 2024-01-03-aws-cloudtrail-stop-logging
description: Detection of adversaries stopping CloudTrail logging to evade detection and operate stealthily within a compromised AWS environment.
date: "2024-01-03T15:00:00Z"
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
  - title: AWS CloudTrail Stop Logging
    description: Detects StopLogging events in AWS CloudTrail to identify potential defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudTrail Stop Logging - Non Console
    description: Detects StopLogging events in AWS CloudTrail excluding console actions
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

This brief focuses on detecting the `StopLogging` event within AWS CloudTrail logs, a tactic used by attackers to evade detection and operate discreetly within compromised AWS environments. The detection excludes benign `StopLogging` actions originating from the AWS console and focuses on successful attempts performed programmatically or through the CLI. By stopping CloudTrail logging, adversaries aim to eliminate traces of their malicious activities, hindering incident response, forensic investigations, and potentially enabling unauthorized access or data exfiltration. This activity can occur after initial access and privilege escalation to allow for unfettered lateral movement and data compromise. The detection logic leverages event data from AWS CloudTrail, specifically focusing on the `StopLogging` event name and its associated parameters.

## Attack Chain

1.  **Initial Compromise:** The attacker gains initial access to the AWS environment, potentially through compromised credentials or exploiting a vulnerability in an EC2 instance.
2.  **Privilege Escalation:** The attacker escalates their privileges within the AWS environment, potentially by exploiting misconfigured IAM roles or policies.
3.  **Identify CloudTrail:** The attacker identifies that CloudTrail is enabled and actively logging events within the AWS environment.
4.  **Attempt StopLogging:** The attacker attempts to stop CloudTrail logging using the AWS CLI or API, issuing the `StopLogging` command.
5.  **Successful StopLogging:** The `StopLogging` command is successfully executed, disabling CloudTrail logging. The event is recorded in CloudTrail before logging is disabled.
6.  **Lateral Movement:** With CloudTrail logging disabled, the attacker moves laterally within the AWS environment, accessing other resources and services without being monitored.
7.  **Data Exfiltration:** The attacker exfiltrates sensitive data from the AWS environment to an external location.
8.  **Persistence:** The attacker establishes persistence within the AWS environment, ensuring continued access even if their initial access method is revoked.

## Impact

Successful disabling of CloudTrail logging allows attackers to operate undetected within an AWS environment, hindering incident response and forensic investigations. This can lead to significant data breaches, unauthorized access to sensitive resources, and long-term damage to the organization's reputation. The impact is magnified in environments with weak access controls and limited monitoring capabilities. Depending on the scope of access, the damage can range from data exfiltration to complete infrastructure compromise.

## Recommendation

*   Deploy the Sigma rule `AWS CloudTrail Stop Logging` to your SIEM and tune for your environment.
*   Investigate any `StopLogging` events in AWS CloudTrail logs, especially those not initiated from the console.
*   Monitor AWS CloudTrail logs for suspicious activity and potential defense evasion techniques.
*   Implement strong IAM policies to restrict access to sensitive AWS resources and prevent unauthorized modification of CloudTrail configurations.

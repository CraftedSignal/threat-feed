---
title: AWS Bedrock Model Invocation Logging Deletion
slug: 2024-05-aws-bedrock-logging-deletion
description: Detection of AWS Bedrock model invocation logging configuration deletion via the DeleteModelInvocationLogging API in CloudTrail logs, potentially indicating an adversary attempting to evade detection of malicious AI model usage.
date: "2024-05-16T15:28:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - bedrock
  - cloudtrail
  - defense-evasion
vendors:
  - AWS
products:
  - Bedrock
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.sumologic.com/blog/defenders-guide-to-aws-bedrock/
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: AWS Bedrock Delete Model Invocation Logging Configuration
    description: Detects deletion of AWS Bedrock model invocation logging configurations via CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Bedrock Logging Configuration Changes by Unusual User Agent
    description: Detects changes to Bedrock logging configuration by unusual user agents which may indicate malicious activity.
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

This threat brief focuses on the deletion of AWS Bedrock model invocation logging configurations, a critical security concern. The detection identifies attempts to remove audit trails by monitoring calls to the `DeleteModelInvocationLoggingConfiguration` API within AWS CloudTrail logs. This activity is significant because adversaries may try to cover their tracks after compromising credentials and using AI models for unauthorized purposes. The deletion of these logs can allow attackers to interact with AI models without being detected, enabling malicious activities such as data exfiltration, prompt injection attacks, or other harmful actions. Defenders must monitor for this behavior to ensure the integrity and auditability of their AI model interactions.

## Attack Chain

1.  **Initial Access:** An attacker gains unauthorized access to an AWS account, potentially through compromised credentials or exploiting a vulnerability in the AWS environment.
2.  **Privilege Escalation (Optional):** The attacker may attempt to escalate privileges within the AWS account to gain the necessary permissions to manage Bedrock logging configurations.
3.  **Discovery:** The attacker identifies that AWS Bedrock model invocation logging is enabled and seeks to disable it to evade detection.
4.  **Disable Logging:** The attacker calls the `DeleteModelInvocationLoggingConfiguration` API to remove the existing logging configuration. This action is recorded in AWS CloudTrail.
5.  **Malicious Model Interaction:** With logging disabled, the attacker interacts with the AWS Bedrock models to conduct unauthorized activities such as data exfiltration, prompt injection, or other forms of malicious model exploitation.
6.  **Data Exfiltration/Prompt Injection:** The attacker uses the models to extract sensitive data or inject malicious prompts to manipulate the model's behavior for nefarious purposes.
7.  **Evasion:** The attacker avoids detection by ensuring that no logs are generated for these interactions.
8.  **Persistence (Optional):** The attacker may establish persistence mechanisms to maintain unauthorized access to the AWS environment for future exploitation.

## Impact

The successful deletion of AWS Bedrock model invocation logging configurations can have significant consequences. By removing these audit trails, adversaries can operate undetected while interacting with AI models for malicious purposes. This can lead to data breaches, prompt injection attacks, or other harmful activities that are difficult to trace back to the attacker. While specific victim counts are unavailable, organizations across various sectors are potentially vulnerable if they utilize AWS Bedrock and do not adequately monitor for this type of activity. The impact includes potential financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the Sigma rule `AWS Bedrock Delete Model Invocation Logging Configuration` to your SIEM and tune it for your environment to detect the deletion of AWS Bedrock model invocation logging configurations (rules).
*   Implement strict access controls and multi-factor authentication to protect AWS accounts from unauthorized access, reducing the risk of credential compromise that leads to the described attack chain (Attack Chain).
*   Regularly review and audit AWS CloudTrail logs to identify any suspicious activities, including attempts to modify or delete logging configurations (logsource).
*   Configure alerts to trigger when the `DeleteModelInvocationLoggingConfiguration` API is called, and investigate any instances of this event (rules).

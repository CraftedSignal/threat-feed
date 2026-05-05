---
title: AWS Bedrock Model Invocation Logging Deletion Attempt
slug: 2024-01-aws-bedrock-logging-deletion
description: Detection of attempts to delete AWS Bedrock model invocation logging configurations, potentially indicating an adversary trying to remove audit trails of model interactions after credential compromise, to hide malicious AI model usage.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - bedrock
  - cloudtrail
  - logging
  - defense-evasion
vendors:
  - Amazon
  - Splunk
products:
  - CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.sumologic.com/blog/defenders-guide-to-aws-bedrock/
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: Detect AWS Bedrock Logging Deletion
    description: Detects attempts to delete AWS Bedrock model invocation logging configurations via CloudTrail logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Bedrock Logging Deletion by Non-Admin User
    description: Detects attempts to delete AWS Bedrock model invocation logging configurations by users who are not typically administrators.
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

This analytic identifies attempts to delete AWS Bedrock model invocation logging configurations. The activity is detected by monitoring AWS CloudTrail logs for calls to the DeleteModelInvocationLogging API. Successful deletion of these logs could allow attackers to interact with AI models hosted on AWS Bedrock without leaving forensic traces. This may be indicative of an adversary who has compromised AWS credentials and is attempting to evade detection of their malicious actions. The impact could range from data exfiltration and prompt injection attacks to other unauthorized activities, all performed without generating audit records. This event should be considered a high-priority alert, as it directly impacts the ability to monitor and respond to potentially malicious use of AI models within the AWS environment. The detection leverages AWS CloudTrail logs and is based on the Splunk ES-CU analytic "AWS Bedrock Delete Model Invocation Logging Configuration".

## Attack Chain

1.  An attacker gains unauthorized access to an AWS account, potentially through credential compromise or other means.
2.  The attacker enumerates the existing AWS Bedrock model invocation logging configurations within the targeted AWS account.
3.  The attacker executes the `DeleteModelInvocationLoggingConfiguration` API call to disable or remove the logging configuration.
4.  AWS CloudTrail logs the `DeleteModelInvocationLoggingConfiguration` event, capturing details such as the user, source IP, and timestamp.
5.  The attacker proceeds to interact with AWS Bedrock models, potentially performing data exfiltration or prompt injection attacks.
6.  Because model invocation logging has been disabled, these interactions are not logged, hindering detection and incident response efforts.
7.  The attacker attempts to further cover their tracks by deleting or modifying other relevant CloudTrail logs.

## Impact

A successful attack could lead to unauthorized access and manipulation of AI models hosted on AWS Bedrock. The deletion of model invocation logs allows attackers to hide their activities, making it difficult to detect and respond to incidents such as data exfiltration or prompt injection attacks. This can result in significant financial loss, reputational damage, and legal liabilities. The exact number of victims and the extent of the damage depend on the scope and duration of the attacker's access to the AI models.

## Recommendation

*   Deploy the Sigma rule `Detect AWS Bedrock Logging Deletion` to your SIEM to detect attempts to delete AWS Bedrock model invocation logging configurations.
*   Investigate any detected instances of `DeleteModelInvocationLoggingConfiguration` events, focusing on unexpected users or source IPs, to validate legitimate administrative actions.
*   Enable AWS CloudTrail logging for all AWS regions and services, including Bedrock, to ensure comprehensive audit coverage.
*   Implement multi-factor authentication (MFA) for all AWS accounts to reduce the risk of credential compromise (T1685.002).
*   Monitor CloudTrail logs for unusual API calls and access patterns to identify potential insider threats or compromised accounts.
*   Review and update IAM policies to enforce the principle of least privilege and restrict access to sensitive API actions, such as `DeleteModelInvocationLoggingConfiguration`.

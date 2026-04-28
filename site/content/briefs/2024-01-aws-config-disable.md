---
title: AWS Config Service Disabling Detection
slug: 2024-01-aws-config-disable
description: Detection of AWS Config Service disabling, potentially indicating an attempt to impair defenses by stopping configuration recording and delivery.
date: "2024-01-02T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - attack.defense-impairment
  - attack.t1562.008
  - aws
vendors:
  - Amazon
products:
  - AWS Config
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-log-files-for-aws-config.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_config_disable_recording.yml
rules:
  - title: AWS Config Delete Delivery Channel
    description: Detects AWS Config Delivery Channel deletion via CloudTrail logs
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1562.008
    data_sources:
      - aws
      - cloudtrail
  - title: AWS Config Stop Configuration Recorder
    description: Detects attempts to stop the AWS Config Configuration Recorder
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1562.008
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

This threat brief focuses on detecting the disabling of AWS Config, a service that continuously monitors and records AWS resource configurations. An attacker might disable AWS Config to evade detection and prevent auditing of their malicious activities within the AWS environment. By deleting delivery channels or stopping the configuration recorder, an attacker can effectively blind the security team to changes made to AWS resources. This activity, if unauthorized, signifies a significant attempt to impair defenses. This brief provides detections based on AWS CloudTrail logs.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account, potentially through compromised credentials or exploiting a vulnerability.
2. The attacker enumerates existing AWS Config resources to identify the delivery channel and configuration recorder.
3. The attacker executes the `DeleteDeliveryChannel` API call to stop the delivery of configuration changes to the designated S3 bucket or SNS topic.
4. The attacker executes the `StopConfigurationRecorder` API call to halt the recording of configuration changes for AWS resources.
5. The attacker performs malicious actions within the AWS environment without the activity being recorded by AWS Config.
6. The attacker may attempt to delete CloudTrail logs, if they have sufficient permissions, to further cover their tracks.
7. The attacker achieves their objective, such as deploying malicious infrastructure, exfiltrating data, or disrupting services, without immediate detection.

## Impact

Successful disabling of AWS Config allows attackers to operate undetected within an AWS environment. This can lead to a delayed response to security incidents, resulting in more significant data breaches, financial losses, or reputational damage. The number of affected AWS accounts and the scope of the damage depend on the attacker's objectives and the duration of the undetected activity.

## Recommendation

*   Deploy the Sigma rule "AWS Config Disabling Channel/Recorder" to your SIEM and tune for your environment to detect unauthorized disabling of AWS Config resources.
*   Review AWS IAM policies to ensure that only authorized personnel have the necessary permissions to modify or disable AWS Config settings.
*   Implement multi-factor authentication (MFA) for all AWS accounts to reduce the risk of credential compromise.
*   Monitor CloudTrail logs for any attempts to disable or modify AWS Config resources, referencing the `eventSource` and `eventName` fields in the provided Sigma rule.

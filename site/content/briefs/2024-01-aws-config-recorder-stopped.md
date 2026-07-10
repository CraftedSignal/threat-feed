---
title: AWS Config Configuration Recorder Stopped
slug: 2024-01-aws-config-recorder-stopped
description: Detection of AWS Config configuration recorder being stopped, potentially by an adversary to evade detection and obscure activity.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - defense-evasion
  - configuration-change
vendors:
  - AWS
products:
  - AWS Config
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/configservice/stop-configuration-recorder.html
  - https://docs.aws.amazon.com/config/latest/APIReference/API_StopConfigurationRecorder.html
rules:
  - title: AWS Config Recorder Stopped
    description: Detects when an AWS Config configuration recorder is stopped.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Config Recorder Stopped by Unusual User Agent
    description: Detects when an AWS Config configuration recorder is stopped by an unusual user agent.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when an AWS Config configuration recorder is stopped. AWS Config recorders continuously track and record configuration changes across supported AWS resources. Stopping the recorder immediately reduces visibility into infrastructure changes and can be abused by adversaries to evade detection, obscure follow-on activity, or weaken compliance and security monitoring controls. This activity is uncommon in steady-state production environments and should be carefully reviewed, especially when performed outside approved maintenance windows or by unexpected principals. The rule focuses on events logged within AWS CloudTrail.

## Attack Chain

1. An attacker gains access to an AWS account, potentially through compromised credentials or an IAM role with excessive permissions.
2. The attacker authenticates to the AWS environment and enumerates existing AWS Config configuration recorders.
3. The attacker issues a `StopConfigurationRecorder` API call, targeting a specific recorder.
4. The AWS Config service processes the request and stops the designated configuration recorder.
5. CloudTrail logs the `StopConfigurationRecorder` event with details about the actor, timestamp, and affected resource.
6. The attacker performs actions to modify or create new resources, without those changes being recorded by Config.
7. These actions may include changing IAM policies, creating EC2 instances, modifying security groups, or deploying infrastructure changes using CloudFormation.
8. The attacker attempts to cover their tracks by deleting relevant CloudTrail logs (if sufficient privileges exist) to further hinder forensic analysis and detection.

## Impact

Stopping the AWS Config recorder creates a blind spot in security monitoring. It allows attackers to make unauthorized configuration changes without being detected by automated compliance checks or security alerts. This can lead to data breaches, privilege escalation, and other security incidents. The scope of the impact depends on the duration the recorder is stopped and the extent of configuration changes made during that period.

## Recommendation

*   Deploy the Sigma rule `AWS Config Recorder Stopped` to your SIEM, ingesting `filebeat-*` and `logs-aws.cloudtrail-*` indices, and tune for your environment.
*   Monitor AWS CloudTrail logs for `StopConfigurationRecorder` events, specifically looking for unexpected principals or activity outside of documented change windows.
*   Review IAM permissions to ensure only a minimal set of trusted roles can stop or modify AWS Config components.
*   Implement guardrails such as AWS Config rules, SCPs, or automated remediation to detect and respond to recorder stoppage.
*   Update monitoring, alerting, and incident response runbooks to explicitly cover AWS Config visibility loss scenarios.

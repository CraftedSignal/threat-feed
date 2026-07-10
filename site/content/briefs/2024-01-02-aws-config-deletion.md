---
title: AWS Config Resource Deletion for Defense Evasion
slug: 2024-01-02-aws-config-deletion
description: An adversary may delete AWS Config resources to evade detection, hide prior activity, or weaken governance controls, which reduces security visibility and auditability within an AWS environment.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - defense-evasion
  - aws
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
  - https://docs.aws.amazon.com/config/latest/developerguide/how-does-config-work.html
  - https://docs.aws.amazon.com/config/latest/APIReference/API_Operations.html
rules:
  - title: AWS Config Resource Deletion
    description: Detects attempts to delete AWS Config resources via CloudTrail logs.
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
  - title: AWS Config Configuration Recorder Deletion
    description: Detects attempts to delete AWS Config Configuration Recorder via CloudTrail logs.
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

AWS Config provides continuous visibility into resource configuration changes and compliance posture across an account. Attackers may attempt to delete AWS Config resources to evade detection, hide prior activity, or weaken governance controls before or after other malicious actions. This activity, if successful, significantly reduces security visibility and auditability. This behavior is uncommon outside of planned infrastructure changes and should be considered high-risk when unexpected. The rule focuses on the successful deletion of AWS Config resources. The AWS environment is a common target, as its misconfiguration or compromise can lead to widespread data breaches and system outages.

## Attack Chain

1. An attacker gains initial access to an AWS account through compromised credentials or a misconfigured IAM role.
2. The attacker enumerates existing AWS Config resources, such as configuration recorders, delivery channels, and config rules, to identify targets for deletion.
3. The attacker attempts to delete AWS Config resources using the AWS CLI, SDK, or management console. Specific API calls include `DeleteConfigRule`, `DeleteDeliveryChannel`, and `DeleteConfigurationRecorder`.
4. The attacker modifies IAM policies to weaken restrictions around Config service actions, if necessary, to facilitate successful deletion.
5. The attacker verifies the deletion of Config resources by checking the AWS Management Console or using the AWS CLI to confirm the absence of the targeted resources.
6. The attacker performs other malicious actions, such as deploying unauthorized resources or exfiltrating data, while evading detection due to the disabled Config service.

## Impact

Successful deletion of AWS Config resources impairs an organization's ability to monitor configuration changes, detect compliance violations, and conduct forensic investigations. This can lead to delayed detection of security incidents, increased risk of data breaches, and difficulty in maintaining regulatory compliance. The number of affected organizations is difficult to quantify, but the impact on each can be significant, potentially leading to data loss, financial penalties, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `AWS Config Resource Deletion` to detect unauthorized attempts to delete AWS Config resources using CloudTrail logs.
*   Enable AWS Config rules or Security Hub controls to alert when Config is disabled or degraded, providing an additional layer of monitoring.
*   Review IAM permissions to ensure only a minimal, well-defined set of roles can manage AWS Config.
*   Use SCPs or IAM conditions to restrict deletion of Config resources in production and security accounts, preventing unauthorized modifications.

---
title: AWS GuardDuty Detector Deletion or Disablement
slug: 2024-01-03-aws-guardduty-disable
description: Attackers may delete or disable AWS GuardDuty detectors to impair defenses and evade detection of malicious activities within the AWS environment.
date: "2024-01-03T17:38:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - defense-impairment
  - aws
  - cloudtrail
vendors:
  - Amazon
products:
  - GuardDuty
references:
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_UpdateDetector.html
  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_suspend-disable.html
  - https://docs.datadoghq.com/security/default_rules/719-39f-9cd/
  - https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-general-policies/ensure-aws-guardduty-detector-is-enabled
  - https://docs.stellarcyber.ai/5.2.x/Using/ML/Alert-Rule-Based-Potentially_Malicious_AWS_Activity.html
  - https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Amazon%20Web%20Services/Analytic%20Rules/AWS_GuardDutyDisabled.yaml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/defense_evasion_guardduty_detector_deletion.toml
  - https://help.fortinet.com/fsiem/Public_Resource_Access/7_4_0/rules/PH_RULE_AWS_GuardDuty_Detector_Deletion.htm
  - https://research.splunk.com/sources/5d8bd475-c8bc-4447-b27f-efa508728b90/
  - https://suktech24.com/2025/07/17/aws-threat-detection-rule-guardduty-detector-disabled-or-suspended/
  - https://www.atomicredteam.io/atomic-red-team/atomics/T156001#atomic-test-46---aws---guardduty-suspension-or-deletion
rules:
  - title: AWS GuardDuty Detector Deletion
    description: Detects successful deletion of an AWS GuardDuty detector.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - aws
      - cloudtrail
  - title: AWS GuardDuty Detector Disablement via UpdateDetector
    description: Detects disabling of an AWS GuardDuty detector using the UpdateDetector API.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - aws
      - cloudtrail
  - title: AWS GuardDuty Detector Update Event
    description: Detects any updates to an AWS GuardDuty detector.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
    data_sources:
      - aws
      - cloudtrail
rules_count: 3
---

Attackers with sufficient AWS privileges may attempt to disable or delete AWS GuardDuty detectors to evade detection. GuardDuty is a threat detection service that monitors AWS accounts for malicious activity. Disabling it allows attackers to operate with less chance of being detected. This activity may occur post-compromise as part of a broader defense evasion strategy, or as a precursor to malicious activities. The deletion or disabling of GuardDuty detectors should be considered a critical event, warranting immediate investigation to verify legitimacy. The references suggest that this behavior has been observed in the wild and is documented across multiple security vendors.

## Attack Chain

1. An attacker gains initial access to an AWS account through compromised credentials or other means (T1078).
2. The attacker enumerates existing GuardDuty detectors to identify the target for disabling or deletion (T1068).
3. The attacker authenticates to the AWS API using stolen credentials or an assumed role with sufficient permissions.
4. The attacker calls the `DeleteDetector` API to remove the GuardDuty detector entirely, erasing all existing findings (T1685.002).
5. Alternatively, the attacker calls the `UpdateDetector` API to disable the detector by setting the `enable` parameter to `false` (T1685.002).
6. AWS CloudTrail logs the `DeleteDetector` or `UpdateDetector` event with a `Success` or `null` error code.
7. With GuardDuty disabled, the attacker performs malicious actions such as lateral movement, data exfiltration, or resource compromise without immediate detection.
8. The attacker attempts to remove CloudTrail logs to further impair defenses (T1562.008).

## Impact

A successful attack can lead to the complete loss of threat detection capabilities within the AWS environment. With GuardDuty disabled, malicious activities can go unnoticed, potentially leading to data breaches, unauthorized access, or resource compromise. The impact is significant because GuardDuty is a primary security control for many organizations using AWS. Depending on the attacker's objectives, this could result in financial loss, reputational damage, or compliance violations. The references suggest that this is a known technique used by attackers to evade detection in AWS environments.

## Recommendation

*   Deploy the Sigma rule "AWS GuardDuty Detector Deleted Or Updated" to your SIEM using AWS CloudTrail logs to detect attempts to disable or delete GuardDuty (logsource: aws, service: cloudtrail).
*   Investigate all instances of `DeleteDetector` and `UpdateDetector` events in CloudTrail, especially if initiated from unusual locations or IAM roles.
*   Implement multi-factor authentication (MFA) for all IAM users to reduce the risk of credential compromise (T1110).
*   Enforce the principle of least privilege by granting only necessary permissions to IAM roles (T1078).
*   Monitor CloudTrail logs for anomalies that could indicate malicious activity following a GuardDuty disablement.

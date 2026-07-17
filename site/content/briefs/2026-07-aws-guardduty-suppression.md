---
title: AWS GuardDuty Detection Suppression
slug: 2026-07-aws-guardduty-suppression
description: 'Adversaries leverage specific AWS GuardDuty API calls including CreateIPSet, UpdateIPSet, CreateThreatIntelSet, UpdateThreatIntelSet, or UpdateDetector with Enable: false to suppress or blind Amazon GuardDuty''s detection capabilities, allowing them to operate undetected within a compromised AWS environment.'
date: "2026-07-17T07:55:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - cloud-security
  - aws
  - guardduty
vendors:
  - Amazon Web Services
products:
  - Amazon GuardDuty
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Identifies attempts to suppress or blind Amazon GuardDuty without deleting the detector outright. Adversaries with GuardDuty permissions can create or update a trusted IP set (CreateIPSet/UpdateIPSet) so that traffic from listed addresses is never flagged, tamper with the threat intelligence feed used to generate findings (CreateThreatIntelSet/UpdateThreatIntelSet), or soft-disable the detector via UpdateDetector with Enable set to false.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_CreateIPSet.html
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_UpdateIPSet.html
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_CreateThreatIntelSet.html
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_UpdateThreatIntelSet.html
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_UpdateDetector.html
  - https://github.com/RhinoSecurityLabs/pacu/tree/master/pacu/modules/guardduty__whitelist_ip
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/defense_evasion_guardduty_finding_suppression.toml
rules:
  - title: AWS GuardDuty Detection Suppression
    description: Identifies attempts to suppress or blind Amazon GuardDuty without deleting the detector outright, by manipulating IP sets, threat intelligence feeds, or soft-disabling the detector via API calls.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
    data_sources:
      - cloud
      - aws.cloudtrail
rules_count: 1
---

Adversaries targeting Amazon Web Services environments have been observed utilizing legitimate GuardDuty API calls to disable or impair its detection mechanisms without outright deleting the service. This defense evasion tactic, described in a rule from Elastic, allows attackers to maintain persistence and operate covertly by preventing GuardDuty from generating findings on their malicious activities. The techniques involve creating or updating trusted IP sets (`CreateIPSet`/`UpdateIPSet`) to whitelist their command and control infrastructure, manipulating threat intelligence feeds (`CreateThreatIntelSet`/`UpdateThreatIntelSet`) to control what GuardDuty identifies as malicious, or soft-disabling the detector (`UpdateDetector` with `Enable: false`). These actions ensure that the GuardDuty detector remains configured and retains historical data, making the tampering less conspicuous than a complete deletion and therefore harder for defenders to detect promptly. This technique impacts any AWS user relying on GuardDuty for threat detection, allowing adversaries to bypass security controls and exfiltrate data or maintain access unnoticed.

## Attack Chain

1. **Initial Access & Privilege Escalation**: An adversary gains initial access to an AWS environment, potentially through compromised credentials or exploitation of a vulnerable application, then escalates privileges to obtain IAM permissions capable of modifying GuardDuty settings.
2. **Defense Evasion - IP Whitelisting**: The attacker executes `CreateIPSet` or `UpdateIPSet` API calls via CloudTrail, supplying a list of IP addresses (typically their C2 infrastructure) to be designated as "trusted."
3. **Activate IP Set**: The trusted IP set is activated with the `activate: true` parameter, causing GuardDuty to ignore traffic originating from the specified addresses.
4. **Defense Evasion - Threat Intelligence Manipulation**: Alternatively, the attacker may use `CreateThreatIntelSet` or `UpdateThreatIntelSet` API calls to register or modify a threat intelligence feed that either omits known malicious indicators or introduces benign ones.
5. **Activate Threat Intel Set**: The manipulated threat intelligence set is activated, effectively controlling GuardDuty's understanding of what constitutes a threat.
6. **Defense Evasion - Soft Disabling Detector**: As another alternative, the attacker may issue an `UpdateDetector` API call with the `Enable` parameter set to `false`, effectively pausing GuardDuty without deleting its configuration or historical data.
7. **Undetected Operations**: With GuardDuty detections suppressed, the adversary proceeds with their objectives, such as data exfiltration or deploying additional malware, without generating security alerts from GuardDuty.

## Impact

Successful exploitation of GuardDuty detection suppression allows adversaries to operate within a compromised AWS environment without triggering alerts, making detection and response significantly more challenging. This enables prolonged unauthorized access, data exfiltration, resource hijacking, or further lateral movement within the cloud infrastructure. The impact is primarily on the confidentiality, integrity, and availability of resources and data protected by GuardDuty. All AWS customers utilizing GuardDuty are potential targets. The primary damage is the complete blindness of a critical security service, allowing the attacker to evade monitoring and achieve their objectives unhindered.

## Recommendation

* Deploy the Sigma rule "AWS GuardDuty Detection Suppression" to your SIEM to detect attempts to tamper with GuardDuty configurations.
* Monitor `aws.cloudtrail` logs for `CreateIPSet`, `UpdateIPSet`, `CreateThreatIntelSet`, `UpdateThreatIntelSet`, and `UpdateDetector` API calls, especially when the `activate` parameter is `true` or the `enable` parameter is `false`.
* Restrict `guardduty:CreateIPSet`, `guardduty:UpdateIPSet`, `guardduty:CreateThreatIntelSet`, `guardduty:UpdateThreatIntelSet`, and `guardduty:UpdateDetector` permissions to a highly limited administrative role, and implement strong access controls and multi-factor authentication for these roles.
* Review GuardDuty configuration changes, particularly those affecting IP sets, threat intelligence sets, or detector enablement status, by cross-referencing `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.type` with expected administrative activities.
* Implement change management processes for legitimate GuardDuty tuning activities to distinguish authorized modifications from malicious attempts, using the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.request_parameters` fields for verification.

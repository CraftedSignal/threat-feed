---
title: Detection of Unauthorized AWS GuardDuty Threat Intelligence Set Deletion
slug: 2026-08-guardduty-intel-deletion
description: Adversaries may delete Amazon GuardDuty threat intelligence sets to blind detection capabilities by removing custom feeds of known-malicious IP addresses and domains.
date: "2026-08-26T13:54:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Amazon
products:
  - GuardDuty
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Deleting a threat intel set degrades GuardDuty's detection capability for known adversary infrastructure, allowing communication with threat-actor-controlled IP ranges to go undetected.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteThreatIntelSet.html
  - https://hackingthe.cloud/aws/avoiding-detection/modify-guardduty-config/
rules:
  - title: AWS GuardDuty Threat Intelligence Set Deleted
    description: Detects the deletion of an Amazon GuardDuty threat intelligence set, which impairs security detection capabilities.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloud
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the GuardDuty threat intel deletion detection rule.
      owner: Detection Engineering
      due: 24h
      evidence: Rule ID 7ba46fa6-496c-4d62-a811-7c221b3d2dd9
  mitigation_plan:
    - priority: immediate
      action: Restrict 'guardduty:DeleteThreatIntelSet' in IAM/SCP policies to security admins only.
      owner: IT Operations
      addresses: T1562.001
      evidence: Response and remediation section
---

Threat intelligence sets in Amazon GuardDuty provide a mechanism for security operations teams to upload custom lists of indicators, such as IP addresses or domains, that the service uses to generate high-priority security findings. An attacker who has achieved sufficient permissions in an AWS environment may intentionally delete these threat intelligence sets to degrade the visibility of GuardDuty. By removing these sets, the adversary effectively disables the detection of traffic associated with their own command-and-control infrastructure or other malicious activity, allowing them to operate within the environment while evading security alerts. This technique is a form of defense evasion intended to impair security monitoring tools and is typically observed after an attacker has established persistence or obtained high-privileged credentials.

## Impact

Successful deletion of a threat intelligence set prevents GuardDuty from flagging traffic related to the indicators contained within the removed list. This can lead to undetected command-and-control communication, data exfiltration, or lateral movement, directly reducing the effectiveness of an organization's cloud security posture.

## Recommendation

- Monitor AWS CloudTrail management events for the 'DeleteThreatIntelSet' action to identify potential attempts to impair security defenses.
- Implement IAM policies or Service Control Policies (SCPs) that restrict the 'guardduty:DeleteThreatIntelSet' permission to a dedicated, limited-access security operations role.
- Audit the frequency and timing of threat intel set deletions to differentiate between planned feed rotations and unauthorized modifications.
- Integrate AWS CloudTrail management events into the SIEM and deploy detection rules to alert on suspicious control-plane modifications.

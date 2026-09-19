---
title: AWS CloudTrail Defense Evasion via DeleteTrail API
slug: 2026-09-aws-cloudtrail-deletion
description: The deletion of AWS CloudTrail trails via the DeleteTrail API is a high-risk indicator of defense evasion or sabotage used to eliminate audit visibility.
date: "2026-09-19T13:20:09Z"
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
  - Amazon
products:
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: This rule identifies the deletion of an AWS log trail using the DeleteTrail API.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/delete-trail.html
rules:
  - title: Detect AWS CloudTrail Trail Deletion
    description: Detects the successful deletion of an AWS CloudTrail trail via the DeleteTrail API, which may indicate defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection for DeleteTrail API calls.
      owner: Detection Engineering
      due: 24h
      evidence: Source document identifies DeleteTrail as a high-risk action.
  mitigation_plan:
    - priority: immediate
      action: Implement SCPs to restrict the DeleteTrail permission.
      owner: Cloud Security
      addresses: T1562.008
      evidence: Source recommends hardening via SCPs.
---

The AWS CloudTrail service provides an essential audit trail of API calls and resource modifications within an AWS environment. Attackers attempting to hide malicious activity often target this logging infrastructure to facilitate defense evasion. The `DeleteTrail` API call allows an authorized identity to remove an established log trail, effectively creating a blind spot in the organization's cloud monitoring and compliance posture. This behavior is frequently associated with the "Impair Defenses" tactic, as documented by MITRE ATT&CK under technique T1562.008. Defenders should monitor for successful `DeleteTrail` events, particularly when initiated by non-administrative accounts, unusual source IP addresses, or unknown user agents, as these may signal active compromise or the final stages of an adversarial campaign aimed at destroying forensic evidence.

## Impact

Successful exploitation of this technique results in the immediate loss of visibility into administrative actions, resource configuration changes, and potential exfiltration activities within an AWS account. If an organization fails to maintain redundant, multi-region, or organization-level logging, the deletion of a single trail can effectively wipe the entire audit history for that account, hindering incident response and forensic investigation efforts.

## Recommendation

* Deploy monitoring for the `DeleteTrail` event in AWS CloudTrail logs to trigger immediate SOC alerts for investigation.
* Hardening: Implement Service Control Policies (SCPs) or AWS Config rules to restrict the ability to call `DeleteTrail` to specific break-glass roles.
* Ensure high-availability logging by configuring organization-level CloudTrail trails with log file integrity validation enabled.
* Prioritize investigation of `DeleteTrail` events involving unexpected user identities, unapproved source IPs, or unfamiliar user agents identified in the telemetry.

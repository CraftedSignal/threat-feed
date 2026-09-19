---
title: AWS GuardDuty Publishing Destination Deletion
slug: 2026-09-aws-guardduty-publishing-deletion
description: Adversaries with administrative access to AWS GuardDuty may delete publishing destinations to break security finding exports, effectively blinding SOC monitoring without triggering detector-disabling alerts.
date: "2026-09-19T13:20:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - defense-evasion
vendors:
  - Amazon
products:
  - GuardDuty
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An adversary with GuardDuty administrative access may delete a publishing destination to prevent findings from reaching external storage or a security operations center.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeletePublishingDestination.html
  - https://hackingthe.cloud/aws/avoiding-detection/modify-guardduty-config/
rules:
  - title: Detect AWS GuardDuty Publishing Destination Deletion
    description: Detects when an Amazon GuardDuty publishing destination is deleted, which may indicate an attempt to impair security monitoring.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review current IAM permissions for GuardDuty administrative actions.
      owner: SOC
      due: 48h
      evidence: Source notes recommend reviewing IAM policies for GuardDuty administrative access.
  hunt_leads:
    - lead: Identify all instances of DeletePublishingDestination in the last 6 months.
      technique_id: T1562.001
      data_needed:
        - CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The rule is based on the event.action DeletePublishingDestination.
  mitigation_plan:
    - priority: medium
      action: Apply Service Control Policies (SCPs) to restrict GuardDuty administrative deletions.
      owner: IT Operations
      addresses: T1562.001
      evidence: Source recommends applying SCPs restricting guardduty:DeletePublishingDestination.
---

Adversaries possessing sufficient AWS administrative privileges may target the GuardDuty configuration to impair security monitoring. Amazon GuardDuty typically exports findings to centralized storage (S3), data lakes (Security Lake), or event buses (EventBridge) for ingestion into a SIEM. By executing the DeletePublishingDestination API call, an attacker severs this telemetry pipeline. 

Crucially, this technique allows the attacker to maintain the GuardDuty detector in an active state, which may prevent alerts that would otherwise trigger if the service itself were disabled. This activity is typically indicative of an attempt to perform unauthorized actions within the AWS environment while ensuring those actions are not correlated or archived for security review. Defenders should monitor for this control-plane modification, as it is highly uncommon in stable production environments.

## Impact

Successful execution results in a loss of visibility into potential threats, as security findings are no longer delivered to external storage or SIEM platforms. This hampers incident response by denying defenders access to historical logs and real-time alerts, potentially allowing a compromise to persist undetected across AWS accounts.

## Recommendation

- Deploy the provided detection rule to monitor for `DeletePublishingDestination` CloudTrail events.
- Implement Service Control Policies (SCPs) or IAM policies to restrict the `guardduty:DeletePublishingDestination` action to a limited set of authorized security operations roles.
- Review IAM permissions for existing identities to identify those with excessive administrative access to GuardDuty.
- Establish alerting for any changes to GuardDuty publishing destinations, prioritizing investigation of deletions that lack a documented change management ticket.

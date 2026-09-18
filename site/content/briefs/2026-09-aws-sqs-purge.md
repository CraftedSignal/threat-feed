---
title: AWS SQS PurgeQueue Defense Evasion
slug: 2026-09-aws-sqs-purge
description: Adversaries may use the PurgeQueue action in AWS Simple Queue Service (SQS) to permanently delete all messages within a queue to disrupt operations, destroy forensic evidence, or evade detection.
date: "2026-09-18T19:27:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - defense-evasion
  - impact
  - aws
vendors:
  - Amazon
products:
  - Simple Queue Service
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries may use this action to... impair monitoring and alerting by removing messages that contain evidence of malicious activity.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Purging an SQS queue permanently deletes all messages currently in the queue.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/defense_evasion_sqs_purge_queue.toml
rules:
  - title: Detect AWS SQS Queue Purge
    description: Detects the successful execution of the SQS PurgeQueue API, which deletes all messages in a queue.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
      - T1562.008
    data_sources:
      - cloud
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to identify SQS PurgeQueue activity
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit logic for identifying this event.
  mitigation_plan:
    - priority: short_term
      action: Review and restrict IAM policies using PurgeQueue
      owner: IT Operations
      addresses: T1562.008
      evidence: Source recommends reinforcing least-privilege IAM policies.
---

AWS SQS is a managed message queuing service utilized for decoupling distributed components and buffering event-driven data. Threat actors may exploit the PurgeQueue API call to execute destructive operations within a cloud environment. By purging a queue, an attacker permanently and irreversibly deletes all pending messages, which can result in operational disruption, loss of critical data, or the destruction of audit trails and security-relevant events buffered within the SQS queue. This behavior is primarily observed as a means to impair detection capabilities or impact business continuity. Security teams should monitor for unauthorized or anomalous execution of this command, particularly when performed by identities lacking clear operational requirements for queue management.

## Impact

Successful execution of this action leads to the permanent loss of all message data contained within the targeted SQS queue. This can cause significant business logic failures in dependent downstream systems, gaps in security logging pipelines that rely on SQS for event ingestion, and the deletion of forensic evidence that would otherwise aid incident response efforts.

## Recommendation

- Implement the detection rule below to alert on the 'PurgeQueue' event in AWS CloudTrail logs.
- Review IAM policies to ensure that the 'sqs:PurgeQueue' permission follows the principle of least privilege.
- Investigate the identity performing the purge by reviewing 'aws.cloudtrail.user_identity.arn' and correlating with other recent activity from the same access key.
- Establish a baseline of authorized maintenance and automated cleanup scripts to reduce noise from legitimate operational activities.
- Deploy the provided detection logic to your SIEM and tune against known automated operational jobs that legitimately utilize the PurgeQueue API.

---
title: AWS SQS Queue Purge Detection
slug: 2024-01-aws-sqs-queue-purge
description: Detection of AWS Simple Queue Service (SQS) queue purging, which adversaries may leverage to disrupt application workflows, destroy operational data, or impair monitoring and alerting systems by removing critical evidence of malicious activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - sqs
  - defense-evasion
  - impact
vendors:
  - AWS
products:
  - Simple Queue Service
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html
  - https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/
  - https://github.com/aws-samples/aws-incident-response-playbooks/blob/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework/tree/a8c7b313636b406a375952ac00b2d68e89a991f2/docs
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS SQS Queue Purge Detected
    description: Detects when an AWS SQS queue is purged, which could indicate malicious activity aimed at disrupting services or evading detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS SQS Queue Purge Initiated by Unusual User Agent
    description: Detects SQS queue purges initiated by a user agent that is not typically associated with administrative tasks, potentially indicating unauthorized activity.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert detects the purging of an AWS Simple Queue Service (SQS) queue. AWS SQS is a managed message queuing service commonly used to decouple services and buffer events across distributed and serverless architectures. Adversaries may abuse the `PurgeQueue` action to remove messages, potentially disrupting application workflows, destroying operational data, or impairing security monitoring and alerting by deleting audit and security events. Defenders should investigate unexpected `PurgeQueue` events, especially in production environments, to determine whether the action aligns with documented procedures and expected operational behavior. The rule focuses on successful `PurgeQueue` events within AWS CloudTrail logs and should be deployed to monitor critical SQS queues.

## Attack Chain

1. An attacker gains access to an AWS account through compromised credentials or a misconfigured IAM role.
2. The attacker identifies SQS queues that contain valuable operational or security-related data.
3. The attacker uses the `aws sqs purge-queue` command or AWS API to purge the targeted queue.
4. The `PurgeQueue` API call is logged as a `PurgeQueue` event in AWS CloudTrail.
5. All messages within the targeted SQS queue are permanently deleted.
6. Downstream systems that rely on messages from the purged queue experience disruption or data loss.
7. Security monitoring systems that ingest logs from the purged queue miss critical security events.
8. The attacker further exploits the environment, potentially performing data exfiltration or other malicious activities, with reduced visibility due to the purged logs.

## Impact

Successful purging of an SQS queue can lead to significant disruption of application workflows and data loss. If the queue contains security-related logs, it can impair monitoring and alerting capabilities, allowing adversaries to operate with reduced visibility. The impact can range from temporary service interruptions to the permanent loss of critical operational data, depending on the purpose and content of the purged queue. This activity could affect a wide range of sectors using AWS SQS, including e-commerce, finance, and healthcare.

## Recommendation

*   Deploy the Sigma rule "AWS SQS Queue Purge Detected" to your SIEM and tune it for your environment to detect unauthorized queue purges in near real-time.
*   Review `aws.cloudtrail.user_identity.arn` and `access_key_id` in CloudTrail logs to determine the identity that initiated the `PurgeQueue` action.
*   Reinforce least-privilege IAM policies to limit which identities can perform the `PurgeQueue` action, as outlined in the AWS Knowledge Center – Security Best Practices.
*   Enhance monitoring and alerting for destructive SQS actions, especially in production environments, using CloudTrail and CloudWatch.
*   Investigate events where `event.action` is `PurgeQueue` and `event.outcome` is `success` in AWS CloudTrail logs.

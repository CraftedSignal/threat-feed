---
title: AWS KMS Customer Managed Key Lifecycle Manipulation
slug: 2026-08-aws-kms-lifecycle-manipulation
description: Adversaries may disable or schedule the deletion of AWS KMS keys to sabotage business operations, render encrypted data unrecoverable, and obstruct forensic investigation or incident response efforts.
date: "2026-08-24T09:49:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - impact
  - cloud-security
  - aws-kms
  - incident-response
vendors:
  - Amazon
products:
  - AWS Key Management Service
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries may use these operations to cause irreversible data loss, disrupt business operations, impede incident response, or hide evidence of prior activity.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/cli/latest/reference/kms/disable-key.html
  - https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html
rules:
  - title: Detect AWS KMS Key Lifecycle Modification
    description: Detects unauthorized attempts to disable or schedule the deletion of AWS customer managed KMS keys, which may indicate sabotage or malicious intent to destroy data access.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Review all existing IAM policies for excessive kms:DisableKey and kms:ScheduleKeyDeletion permissions.
      owner: Cloud Security
      due: 48h
      evidence: Strengthen controls by restricting KMS lifecycle permissions
  enrichment_needed:
    - item: User agent inventory
      owner: SOC
      reason: To identify all legitimate automation tools for inclusion in detection filters.
      evidence: False positive analysis
  hunt_leads:
    - lead: Search for all DisableKey and ScheduleKeyDeletion events from the past 6 months to identify anomalies.
      technique_id: T1485
      data_needed:
        - CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Because these operations are rare, they should be treated as high-risk.
  mitigation_plan:
    - priority: immediate
      action: Implement SCPs to prevent deletion of critical production KMS keys.
      owner: IT Operations
      addresses: T1485
      evidence: Use AWS Organizations SCPs to prevent KMS key deletion in production accounts.
  gaps:
    - Lack of automated response playbooks for immediate CancelKeyDeletion actions.
---

Adversaries targeting AWS environments may attempt to disable or schedule the deletion of Customer Managed KMS keys to disrupt service availability and cause permanent data loss. Because KMS keys underpin the encryption for critical services such as S3, EBS, RDS, Secrets Manager, and Lambda, controlling these keys provides an attacker with a high-impact lever to sabotage an organization. This activity is typically observed in later stages of an intrusion, where an attacker seeks to hide evidence of prior exfiltration, prevent recovery from ransomware, or impede incident response by destroying access to encrypted forensic data and backups. Defenders should monitor for highly privileged KMS lifecycle API calls that deviate from established infrastructure-as-code deployment patterns.

## Attack Chain

1. Attacker gains initial access to the AWS environment through compromised IAM credentials or over-privileged service roles.
2. Attacker performs internal reconnaissance to identify critical KMS keys and the AWS services they protect (e.g., S3 buckets, RDS instances).
3. Attacker uses compromised credentials to execute the `DisableKey` API call via AWS CLI or SDK to immediately halt encryption/decryption operations for targeted services.
4. Attacker monitors service health or application logs to confirm the disruption of operations.
5. Attacker executes the `ScheduleKeyDeletion` API call, initiating a mandatory waiting period before the key and its associated material are permanently destroyed.
6. Attacker leverages the resulting downtime or recovery chaos to exfiltrate remaining data or obfuscate their activities.
7. Attacker objective achieved: permanent data loss and environmental sabotage.

## Impact

Successful manipulation of KMS lifecycle states results in immediate loss of access to encrypted data stored in S3, EBS volumes, or RDS databases. Once the pending deletion window expires, this data becomes permanently unrecoverable, causing severe business disruption, potential regulatory compliance failures, and the total loss of forensic evidence required for incident response.

## Recommendation

- Deploy the provided detection rule to monitor for `DisableKey` and `ScheduleKeyDeletion` events in AWS CloudTrail logs.
- Restrict the `kms:DisableKey` and `kms:ScheduleKeyDeletion` permissions to a minimal set of highly privileged administrator identities using IAM policies or Service Control Policies (SCPs).
- Enable AWS Config rules to monitor and alert on the state of KMS keys.
- Require multi-factor authentication (MFA) for all IAM principals authorized to perform KMS management operations.
- Implement tagging and naming conventions to distinguish between critical production KMS keys and ephemeral keys used in CI/CD pipelines to reduce false positives in detections.

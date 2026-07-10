---
title: AWS KMS Customer Managed Key Disabled or Scheduled for Deletion
slug: 2024-01-aws-kms-deletion
description: An adversary may disable or schedule the deletion of an AWS customer-managed KMS Key to cause irreversible data loss, disrupt business operations, impede incident response, or hide evidence of prior activity.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - kms
  - datadestruction
vendors:
  - AWS
products:
  - AWS Key Management Service (KMS)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://docs.aws.amazon.com/cli/latest/reference/kms/disable-key.html
  - https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS KMS Key DisableKey Activity
    description: Detects DisableKey API calls in AWS KMS
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
      - T1485.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS KMS Key ScheduleKeyDeletion Activity
    description: Detects ScheduleKeyDeletion API calls in AWS KMS
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
      - T1485.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

AWS KMS keys are critical for encryption across various AWS services like S3, EBS, and RDS. Disabling or scheduling a KMS key for deletion disrupts encryption and decryption workflows, potentially rendering data unrecoverable. The Elastic detection rule published on 2026-04-10 identifies attempts to disable or schedule the deletion of an AWS customer-managed KMS Key. These actions are typically rare, privileged, and tightly controlled, making unexpected instances high-risk. Adversaries might target KMS keys to sabotage recovery, impede forensic analysis, or destroy evidence. Defenders should prioritize monitoring KMS key lifecycle changes due to their potential for significant impact on data availability and business operations.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account.
2. The attacker escalates privileges to obtain the necessary KMS permissions.
3. The attacker uses the AWS CLI or API to execute the `DisableKey` command, specifying the ARN of the target KMS key.
4. Alternatively, the attacker uses the AWS CLI or API to execute the `ScheduleKeyDeletion` command, specifying the ARN of the target KMS key and a pending window in days.
5. CloudTrail logs the `DisableKey` or `ScheduleKeyDeletion` event with a status of "success".
6. If `DisableKey` was used, dependent services immediately begin failing or experience decryption errors.
7. If `ScheduleKeyDeletion` was used, the key enters a pending deletion state for the specified number of days.
8. Upon deletion, all data encrypted with the key becomes unrecoverable, leading to data loss and disruption of services.

## Impact

Disabling or deleting KMS keys can have severe consequences, potentially impacting numerous AWS services relying on the key for encryption, including S3, EBS, RDS, Secrets Manager, and Lambda. This can lead to data unavailability, service disruptions, and irreversible data loss. The scope of impact depends on the criticality of the data protected by the key and the number of services affected. Successful execution of this attack can impede incident response efforts and result in significant financial and reputational damage.

## Recommendation

*   Deploy the "AWS KMS Customer Managed Key Disabled or Scheduled for Deletion" Sigma rule to detect unauthorized KMS key lifecycle changes (rule.name).
*   Monitor AWS CloudTrail logs for `DisableKey` and `ScheduleKeyDeletion` events to detect potentially malicious activity (index).
*   Restrict AWS KMS lifecycle permissions (`kms:DisableKey`, `kms:ScheduleKeyDeletion`) to a minimal set of privileged users and roles (references).
*   Implement multi-factor authentication (MFA) for administrators with KMS key management permissions to prevent unauthorized access (Security Best Practices reference).
*   Enable AWS Config rules for KMS key state monitoring to continuously assess the configuration of KMS keys and detect deviations from desired states (Security Best Practices reference).

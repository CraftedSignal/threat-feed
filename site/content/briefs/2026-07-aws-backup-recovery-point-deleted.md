---
title: AWS Backup Recovery Point Deletion as Anti-Recovery Tactic
slug: 2026-07-aws-backup-recovery-point-deleted
description: Adversaries are leveraging the AWS Backup `DeleteRecoveryPoint` API call by non-service principals to remove critical data backups, a high-signal anti-recovery technique observed in ransomware and data-destruction attacks that prevents victims from restoring associated data.
date: "2026-07-03T15:54:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - anti-recovery
  - ransomware
  - data-destruction
vendors:
  - Amazon
products:
  - AWS Backup
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Identifies deletion of an AWS Backup recovery point via DeleteRecoveryPoint. A recovery point is a stored backup of a protected resource... Deleting recovery points removes the ability to restore the associated data and is a core anti-recovery technique used in ransomware and data-destruction attacks.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_backup_recovery_point_deleted.toml
  - https://docs.aws.amazon.com/aws-backup/latest/devguide/API_DeleteRecoveryPoint.html
  - https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html
rules:
  - title: AWS Backup Recovery Point Deleted
    description: Detects the deletion of an AWS Backup recovery point by a non-service principal using the `DeleteRecoveryPoint` API call, which is a critical anti-recovery technique.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - cloud
      - aws
rules_count: 1
---

Threat actors are employing a critical anti-recovery technique by deleting AWS Backup recovery points via the `DeleteRecoveryPoint` API call. This action, when performed by a non-service principal (i.e., not the AWS Backup service itself), is a strong indicator of malicious activity. AWS Backup recovery points are essential for restoring various protected resources such as EBS volumes, RDS databases, DynamoDB tables, EFS file systems, and S3 buckets. The deletion of these recovery points is a core tactic in ransomware and data-destruction campaigns, as it directly compromises an organization's ability to recover data, thereby maximizing the impact of an attack and increasing pressure on victims. Defenders should prioritize detection and response to such events, investigating the involved principal, affected recovery points, and any correlation with other destructive or evasive activities to prevent irrecoverable data loss.

## Attack Chain

1.  **Initial Access / Privilege Escalation**: An attacker gains unauthorized access to an AWS account, potentially via compromised credentials, misconfigured access policies, or vulnerability exploitation, and obtains sufficient privileges to interact with AWS Backup.
2.  **Reconnaissance**: The attacker identifies critical AWS Backup recovery points and their associated vaults, determining which protected resources (e.g., EBS, RDS, S3) are most valuable to target for disruption.
3.  **Credential Usage**: Using compromised AWS credentials (e.g., an IAM user or assumed role), the attacker authenticates to the AWS environment.
4.  **Anti-Recovery Action**: The attacker invokes the `DeleteRecoveryPoint` API call, specifying the recovery points to be removed.
5.  **Backup Deletion**: The AWS Backup service processes the malicious request and permanently deletes the specified recovery points from their respective vaults.
6.  **Impact Maximization**: The successful deletion prevents the target organization from restoring backed-up data, thereby maximizing the damage from subsequent data encryption or destruction, or increasing leverage in ransomware demands.

## Impact

The observed deletion of AWS Backup recovery points has severe consequences, directly eliminating an organization's ability to restore critical data from backups. This technique is specifically designed to maximize the impact of ransomware or data-destruction attacks, often leading to significant operational disruption, irreversible data loss, and substantial financial costs associated with business interruption and recovery efforts. If multiple recovery points or entire vaults are targeted, the potential for widespread data unavailability across an organization's cloud infrastructure is high, rendering recovery attempts extremely difficult without external assistance or succumbing to attacker demands.

## Recommendation

*   Deploy the Sigma rule "AWS Backup Recovery Point Deleted" in this brief to your SIEM and tune for your environment, paying close attention to `aws.cloudtrail.user_identity.arn`.
*   Ensure AWS CloudTrail management events are enabled for AWS Backup and ingested into your SIEM for comprehensive monitoring, as required by the detection rule's `logsource`.
*   Rotate or restrict credentials for any principal identified in `aws.cloudtrail.user_identity.arn` if unauthorized `DeleteRecoveryPoint` activity is suspected.
*   Implement strong IAM and SCP policies to restrict `backup:DeleteRecoveryPoint` permissions to a very small set of trusted administrators only.
*   Preserve any remaining backups and consider enabling AWS Backup Vault Lock on critical vaults to prevent future deletions, referencing the `https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html` documentation.

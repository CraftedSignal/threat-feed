---
title: AWS Backup Vault Deleted or Vault Lock Removed
slug: 2026-07-aws-backup-vault-deleted-lock-removed
description: An adversary is detected performing anti-recovery actions in AWS Backup by deleting backup vaults or removing their Vault Lock configurations via the DeleteBackupVault or DeleteBackupVaultLockConfiguration API calls, serving as a strong precursor to ransomware or data destruction, preventing organizations from restoring critical data.
date: "2026-07-03T15:49:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud-security
  - aws
  - anti-recovery
  - defense-evasion
  - impact
vendors:
  - Amazon Web Services
products:
  - AWS Backup
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: A backup vault stores recovery points, and Vault Lock enforces WORM (write-once, read-many) immutability that prevents recovery points from being deleted before their retention expires.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Removing the lock defeats the primary control designed to stop ransomware from destroying backups, and deleting the vault removes the backup container entirely.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_backup_vault_deleted_or_lock_removed.toml
  - https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html
  - https://docs.aws.amazon.com/aws-backup/latest/devguide/API_DeleteBackupVault.html
  - https://docs.aws.amazon.com/aws-backup/latest/devguide/API_DeleteBackupVaultLockConfiguration.html
rules:
  - title: AWS Backup Vault Deleted or Vault Lock Removed
    description: Detects attempts by non-service principals to delete an AWS Backup vault or remove its Vault Lock configuration, which are critical anti-recovery actions often associated with ransomware or data destruction.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1490
      - T1562
    data_sources:
      - cloudtrail
rules_count: 1
---

This threat brief details the detection of critical anti-recovery actions within Amazon Web Services (AWS) Backup. Adversaries who have gained unauthorized access to an AWS environment may invoke the `DeleteBackupVault` or `DeleteBackupVaultLockConfiguration` API calls. These actions are highly impactful because they target an organization's ability to recover from data loss incidents. Removing a Vault Lock defeats the immutability policy designed to protect backups from premature deletion, while deleting an entire backup vault irrevocably destroys all contained recovery points. These activities are rarely observed in legitimate operations and serve as strong indicators of an imminent or ongoing ransomware attack, data destruction, or an attempt to cover tracks following data exfiltration. The threat specifically targets the AWS Backup service, aiming to eliminate recovery options and exacerbate the impact of malicious activity.

## Attack Chain

1.  An adversary obtains valid AWS credentials (e.g., IAM user, role access key) through various initial access vectors, gaining unauthorized access to the target AWS account.
2.  The adversary enumerates AWS resources to identify critical AWS Backup vaults containing recovery points that need to be neutralized.
3.  To overcome existing immutability policies, the adversary executes the `DeleteBackupVaultLockConfiguration` API call to remove the governance-mode lock from a targeted backup vault.
4.  Subsequently, the adversary executes the `DeleteBackupVault` API call to entirely delete the identified backup vault and its associated recovery points.
5.  These API calls are specifically chosen and executed to prevent the victim organization from restoring data from backups.
6.  The ultimate objective is to inhibit system recovery, making the organization more susceptible to ransomware demands, facilitating data destruction, or covering tracks for data exfiltration.

## Impact

The primary impact of successfully deleting AWS Backup vaults or removing Vault Locks is the catastrophic loss of an organization's ability to recover from data loss, ransomware attacks, or accidental deletion. This renders critical data irretrievable, leading to prolonged downtime, significant financial losses due to operational disruption and potential ransom payments, and severe reputational damage. The inability to restore from backups can force organizations to pay ransoms, rebuild systems from scratch, or permanently lose vital business data. While no specific victim counts or sectors are provided in the source, any organization leveraging AWS Backup for disaster recovery is vulnerable.

## Recommendation

*   Deploy the provided Sigma rule "AWS Backup Vault Deleted or Vault Lock Removed" to your SIEM and tune it for your environment.
*   Ensure AWS CloudTrail management events for AWS Backup are enabled and ingested into your security monitoring platform to activate the rule.
*   Implement strict Identity and Access Management (IAM) policies that restrict `backup:DeleteBackupVault` and `backup:DeleteBackupVaultLockConfiguration` permissions to only highly privileged, break-glass roles.
*   Regularly audit access to AWS credentials, especially those identified in `aws.cloudtrail.user_identity.arn`, and review `source.ip` and `user_agent.original` for suspicious origins when this detection triggers.
*   In the event of a detection, immediately review the affected vault from `aws.cloudtrail.request_parameters` and determine if it contained recovery points, then secure remaining recovery points and re-apply Vault Lock if unauthorized.

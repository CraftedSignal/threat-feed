---
title: AWS EC2 EBS Snapshot Access Permissions Removed
slug: 2024-01-aws-ebs-snapshot-access-removed
description: Detection of AWS EC2 EBS snapshot access permissions removal can indicate malicious attempts to disrupt data recovery, evade detection, or maintain exclusive backup access, leading to increased attack impact and incident response complexity.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ebs
  - snapshot
  - impact
vendors:
  - AWS
products:
  - EC2
  - EBS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
references:
  - https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.html
  - https://attack.mitre.org/techniques/T1485/
  - https://attack.mitre.org/techniques/T1490/
  - https://attack.mitre.org/techniques/T1578/
  - https://attack.mitre.org/techniques/T1578/005/
rules:
  - title: AWS EBS Snapshot Access Removal
    description: Detects the removal of access permissions from AWS EC2 EBS snapshots via the ModifySnapshotAttribute API call.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
      - T1490
      - T1578
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EBS Snapshot Delete Protection Removal
    description: Detects when delete protection is removed from an AWS EC2 EBS snapshot via the ModifySnapshotAttribute API call.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
      - T1490
      - T1578
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies the removal of access permissions from shared AWS EC2 EBS snapshots using AWS CloudTrail logs. EBS snapshots are critical for data retention and disaster recovery. Threat actors may attempt to revoke or modify snapshot permissions to prevent legitimate users or processes from accessing backups, which hinders recovery efforts following data loss or destructive actions. This tactic can also be employed to evade detection or maintain exclusive access to sensitive backups, amplifying the impact of attacks and complicating incident response. This behavior matters because successful removal of access can significantly delay or prevent data recovery, leading to prolonged downtime and potential data loss. The rule focuses on identifying `ModifySnapshotAttribute` events where access is being removed, specifically looking for changes to `CREATE_VOLUME_PERMISSION` via `remove=`.

## Attack Chain

1.  The attacker gains unauthorized access to an AWS account, possibly through compromised credentials or exploiting IAM misconfigurations.
2.  The attacker enumerates available EC2 EBS snapshots within the targeted AWS environment to identify potential targets for disruption.
3.  The attacker uses the `ModifySnapshotAttribute` API call to remove access permissions from the identified EBS snapshots, specifically targeting the `CREATE_VOLUME_PERMISSION` attribute.
4.  The request parameters in the CloudTrail logs indicate the removal of access, observed through the presence of `"attributeType=CREATE_VOLUME_PERMISSION"` and `"remove="`.
5.  Legitimate users or automated processes attempting to restore data from the affected snapshots will fail, hindering recovery efforts.
6.  The attacker may repeat the process across multiple snapshots to maximize the impact and disrupt the entire recovery strategy.
7.  The attacker may also delete snapshots entirely using `DeleteSnapshot` to ensure complete data loss.
8.  The attacker achieves their objective of disrupting business operations, holding data for ransom, or covering tracks by preventing forensic analysis and recovery.

## Impact

Successful removal of EBS snapshot access can have significant consequences. Organizations may face extended downtime, data loss, and reputational damage. Depending on the criticality of the affected systems, financial losses and regulatory penalties may also occur. The number of victims and sectors targeted can vary, but any organization relying on AWS for data storage and backup is potentially at risk. If the attack succeeds, the organization's ability to recover from data loss events like ransomware or accidental deletion is severely compromised, potentially leading to irreversible data loss.

## Recommendation

*   Deploy the Sigma rule `AWS EBS Snapshot Access Removal` to detect unauthorized modification of snapshot access permissions in your AWS environment. Enable AWS CloudTrail logging and ensure logs are ingested to your SIEM (Security Information and Event Management) to enable the rule.
*   Review IAM policies and restrict `ec2:ModifySnapshotAttribute` permissions to only trusted administrative roles as mentioned in the rule's investigation steps.
*   Enable AWS Config rules and Security Hub controls such as `ebs-snapshot-public-restorable-check` to provide continuous monitoring and compliance checks, as recommended in the rule's response section.
*   Implement backup immutability using AWS Backup Vault Lock or S3 Object Lock to protect against unauthorized modifications, as mentioned in the response section.
*   Investigate any alerts generated by the Sigma rule, examining `aws.cloudtrail.user_identity.arn` and `source.ip` to identify the actor and source of the access removal, as indicated in the rule's triage section.

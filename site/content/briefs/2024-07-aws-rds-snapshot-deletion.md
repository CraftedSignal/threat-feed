---
title: AWS RDS Snapshot Deletion Detected
slug: 2024-07-aws-rds-snapshot-deletion
description: The deletion of AWS RDS DB snapshots or disabling backups via configuration changes can inhibit recovery, destroy forensic evidence, and prepare for destructive actions by adversaries.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - rds
  - snapshot
  - backup
  - datadestruction
vendors:
  - AWS
products:
  - Amazon RDS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteSnapshot.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBSnapshot.html
  - https://attack.mitre.org/techniques/T1485/
  - https://attack.mitre.org/techniques/T1490/
rules:
  - title: Detect AWS RDS Snapshot Deletion
    description: Detects deletion of RDS snapshots via CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS RDS Cluster Snapshot Deletion
    description: Detects deletion of RDS cluster snapshots via CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Disabling of RDS Backups
    description: Detects disabling of RDS backups by setting backupRetentionPeriod to 0.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - cloudtrail
      - aws
rules_count: 3
---

This rule detects the deletion of AWS RDS DB snapshots or configuration changes that effectively remove backup coverage for a DB instance. RDS snapshots contain full backups of database instances, and disabling automated backups by setting "backupRetentionPeriod=0" has a similar impact by preventing future restore points. A threat actor with sufficient AWS permissions may delete snapshots or disable backups to inhibit recovery, destroy forensic evidence, or prepare for follow-on destructive actions such as instance or cluster deletion. The rule focuses on successful snapshot deletions and backup disabling events within AWS RDS. The scope includes any AWS environment utilizing RDS for database services.

## Attack Chain

1.  The attacker gains access to an AWS account with sufficient permissions to manage RDS instances and snapshots, possibly through compromised credentials or an IAM role with excessive privileges.
2.  The attacker enumerates available RDS DB instances and snapshots within the target AWS account using AWS CLI or API calls (e.g., `DescribeDBSnapshots`, `DescribeDBInstances`).
3.  The attacker identifies target DB instances and their associated snapshots that are critical for recovery or contain valuable forensic data.
4.  The attacker deletes RDS DB snapshots using the `DeleteDBSnapshot` API call, effectively removing restore points.
5.  Alternatively, the attacker modifies the DB instance configuration using the `ModifyDBInstance` API call, setting `backupRetentionPeriod` to 0 to disable automated backups and prevent future restore points.
6.  The attacker may then delete the RDS instance itself using DeleteDBInstance.
7.  The attacker attempts to cover their tracks by deleting relevant CloudTrail logs or disabling CloudTrail logging.
8.  The attacker's objective is to prevent restoration to a known-good state and destroy forensic evidence of attacker actions, potentially as part of a ransomware attack or data exfiltration attempt.

## Impact

Successful deletion of RDS snapshots or disabling of backups can lead to significant data loss and prolonged downtime, making recovery from security incidents or operational failures difficult or impossible. This can impact business continuity, data integrity, and regulatory compliance. The precise impact depends on the criticality of the affected databases and the availability of alternative backup mechanisms. If successful, this can result in total data loss for the organization.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious `DeleteDBSnapshot`, `DeleteDBClusterSnapshot`, or `ModifyDBInstance` events setting `backupRetentionPeriod=0` in AWS CloudTrail logs.
*   Restrict IAM permissions for `rds:DeleteDBSnapshot`, `rds:DeleteDBClusterSnapshot`, and `rds:ModifyDBInstance` (especially backup and deletion-related parameters) to a small set of privileged roles, as described in the remediation steps.
*   Use AWS Config rules and/or Security Hub controls to detect instances with `backupRetentionPeriod=0`, as recommended in the hardening and preventive controls section.

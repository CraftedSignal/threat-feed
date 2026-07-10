---
title: AWS RDS DB Instance Restored for Defense Evasion or Data Collection
slug: 2024-01-09-aws-rds-restore
description: Detection of AWS RDS database instance restoration from a snapshot or S3 backup, potentially indicating unauthorized data access, defense evasion, or data collection by adversaries recreating database environments to bypass controls or exfiltrate sensitive data.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - rds
  - defense-evasion
  - data-collection
vendors:
  - AWS
products:
  - RDS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromDBSnapshot.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromS3.html
  - https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/rds__explore_snapshots/main.py
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-rds-post-exploitation#rds-createdbsnapshot-rds-restoredbinstancefromdbsnapshot-rds-modifydbinstance
rules:
  - title: AWS RDS DB Instance Restored
    description: Detects the restoration of an AWS RDS database instance from a snapshot or S3 backup.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1074.002
      - T1578.004
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS RDS Restore Request Parameters
    description: Detects RDS restore operations with unusual parameters like public accessibility or altered security groups.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1578
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS RDS Restore using unusual Access Key
    description: Detects AWS RDS restore operations using unusual or unknown access keys
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1578
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 3
---

This rule detects the restoration of an AWS RDS database instance, a technique that can be abused by adversaries for defense evasion or data collection. Attackers may restore databases from snapshots or S3 backups to bypass logging and monitoring, create shadow environments for data exfiltration, or access older data. The activity is triggered by the successful execution of `RestoreDBInstanceFromDBSnapshot` or `RestoreDBInstanceFromS3` events within AWS CloudTrail logs. Defenders should monitor for unexpected RDS restores to identify potential malicious activity and data compromise. This activity can occur post-compromise after an attacker gains access to AWS credentials with sufficient privileges to manage RDS instances.

## Attack Chain

1. An attacker gains access to an AWS account through compromised credentials or privilege escalation.
2. The attacker enumerates available RDS snapshots and S3 backups using AWS CLI or API calls (`DescribeDBSnapshots`, `DescribeDBInstances`).
3. The attacker identifies a target RDS database instance containing sensitive data.
4. The attacker initiates a `RestoreDBInstanceFromDBSnapshot` or `RestoreDBInstanceFromS3` operation to create a new RDS instance from a snapshot or backup.
5. A new RDS instance is created with the data from the snapshot or backup.
6. The attacker accesses the restored database instance, bypassing monitoring on the original instance.
7. The attacker exfiltrates sensitive data from the restored instance.
8. The attacker may attempt to delete the restored instance and snapshots to remove traces of their activity.

## Impact

Successful exploitation allows attackers to bypass existing security controls and gain unauthorized access to sensitive data stored within the RDS database. This can lead to data breaches, financial loss, and reputational damage. If the attacker gains access to a production database copy, the impact can be significant, potentially affecting thousands of users. The sectors most likely impacted include those that rely heavily on cloud-based database solutions, such as finance, healthcare, and technology.

## Recommendation

*   Deploy the Sigma rule "AWS RDS DB Instance Restored" to your SIEM, tuned for your specific environment, to detect unauthorized RDS instance restorations.
*   Enforce least privilege for `rds:RestoreDBInstanceFromDBSnapshot` and `rds:RestoreDBInstanceFromS3` actions using IAM policies, restricting restore actions by network, principal, or region.
*   Enable AWS CloudTrail logging and monitor for unexpected RDS events, focusing on `RestoreDBInstanceFromDBSnapshot` and `RestoreDBInstanceFromS3` actions.
*   Implement AWS Config and Security Hub controls for monitoring unapproved RDS restores and misconfigured restored instances.
*   Investigate any alerts generated by the Sigma rule, focusing on the user identity, source IP, and the snapshot or S3 location used for the restore.

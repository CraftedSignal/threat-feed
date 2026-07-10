---
title: AWS RDS DB Snapshot Shared with Another Account
slug: 2024-11-aws-rds-snapshot-shared
description: An AWS RDS DB snapshot is shared with another AWS account or made public, potentially enabling unauthorized access, offline analysis, or data exfiltration by allowing adversaries to restore the snapshot in their controlled infrastructure.
date: "2024-11-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - rds
  - snapshot
  - exfiltration
vendors:
  - AWS
products:
  - AWS RDS
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBSnapshotAttribute.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-rds-post-exploitation#rds-modifydbsnapshotattribute-rds-createdbsnapshot
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_rds_snapshot_shared_with_another_account.toml
rules:
  - title: AWS RDS DB Snapshot Shared with Another Account (Sigma)
    description: Detects when an AWS RDS DB snapshot is shared with another AWS account using CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS RDS DB Cluster Snapshot Shared with Another Account (Sigma)
    description: Detects when an AWS RDS DB Cluster snapshot is shared with another AWS account using CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

This threat focuses on the exfiltration of data from AWS RDS DB snapshots. Adversaries with valid credentials or through misconfigurations may modify snapshot attributes to grant access to accounts they control, bypassing existing security measures. This allows the attacker to restore the snapshot in an environment they control, enabling unauthorized access, offline analysis, or data exfiltration. The attack starts when modifications are made to snapshot attributes adding one or more additional AWS accounts to the snapshot's restore permissions. The rule "AWS RDS DB Snapshot Shared with Another Account" from Elastic detects these successful modifications. This is a critical issue, as DB snapshots contain complete backups of database instances, including schemas, table data, and sensitive application content.

## Attack Chain

1.  **Initial Access:** The attacker gains access to an AWS account through compromised credentials or exploiting a misconfiguration.
2.  **Discovery:** The attacker uses reconnaissance actions such as `DescribeDBSnapshots` or `DescribeDBInstances` to identify valuable RDS DB snapshots.
3.  **Privilege Escalation (Optional):** The attacker may attempt to escalate privileges using techniques like `AttachRolePolicy`, `PutUserPolicy`, or `AssumeRole` to gain the necessary permissions to modify snapshot attributes.
4.  **Modify DBSnapshotAttribute:** The attacker modifies the snapshot's attributes using the `ModifyDBSnapshotAttribute` or `ModifyDBClusterSnapshotAttribute` API calls, adding the attacker's AWS account to the restore permissions.
5.  **Snapshot Copying (Optional):** The attacker may copy the snapshot using the `CopyDBSnapshot` event to another region or account under their control.
6.  **Snapshot Restoration:** The attacker restores the snapshot in their AWS environment. This creates a new DB instance or cluster with the data from the snapshot.
7.  **Data Exfiltration:** The attacker accesses the restored database instance and extracts the sensitive data.
8.  **Cleanup (Optional):** The attacker may attempt to cover their tracks by deleting CloudTrail logs or modifying other security configurations.

## Impact

Successful exploitation allows the attacker to exfiltrate sensitive data contained within the RDS DB snapshot. The number of potential victims is dependent on how widely these snapshots are shared and on the value of the data contained within. Sectors that rely heavily on cloud databases are at increased risk. Consequences of successful attacks include data breaches, financial loss, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the provided Elastic EQL rule "AWS RDS DB Snapshot Shared with Another Account" to your SIEM to detect unauthorized snapshot modifications, tuning it for your environment.
*   Restrict snapshot sharing using IAM condition keys (`kms:ViaService`, `rds:dbSnapshotArn`, `aws:PrincipalArn`) as noted in the overview, and remediate existing cross-account access.
*   Enable AWS Config rules and Security Hub controls for public or cross-account snapshot access, based on the recommendation in the overview section.
*   Monitor AWS CloudTrail logs for `ModifyDBSnapshotAttribute` and `ModifyDBClusterSnapshotAttribute` events (as seen in the Attack Chain) to identify suspicious activity.

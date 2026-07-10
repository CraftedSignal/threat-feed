---
title: AWS RDS DB Instance or Cluster Deleted
slug: 2024-01-aws-rds-deletion
description: An adversary with sufficient permissions may delete RDS resources such as DB instances or clusters to impede recovery, destroy evidence, or inflict operational impact on the environment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - rds
  - datadestruction
vendors:
  - AWS
products:
  - Amazon RDS
  - Amazon Aurora
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBCluster.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteGlobalCluster.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBInstance.html
  - https://github.com/aws-samples/aws-incident-response-playbooks/blob/c151b0dc091755fffd4d662a8f29e2f6794da52c/playbooks/
  - https://github.com/aws-samples/aws-customer-playbook-framework/tree/a8c7b313636b406a375952ac00b2d68e89a991f2/docs
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS RDS DB Instance or Cluster Deleted
    description: Detects the deletion of an Amazon RDS DB instance, Aurora cluster, or global database cluster.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
  - title: AWS RDS Deletion Protection Disabled
    description: Detects when the deletion protection setting is disabled on an AWS RDS instance.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The deletion of Amazon RDS DB instances, Aurora clusters, or global database clusters can lead to permanent data loss and major service disruption. This activity is often carried out by adversaries who have gained sufficient permissions within an AWS environment. The motivation behind such actions can range from impeding recovery efforts following a ransomware attack, destroying critical evidence to hinder forensic investigations, or directly inflicting operational impact on the targeted environment. Defenders should be aware that these actions are irreversible without backups, making swift detection and validation essential to mitigate potential damage.

## Attack Chain

1. An adversary gains initial access to the AWS environment, potentially through compromised credentials or an IAM role with excessive permissions.
2. The attacker enumerates existing RDS DB instances, Aurora clusters, or global database clusters within the target AWS account to identify valuable targets.
3. The attacker modifies the deletionProtection setting on the target RDS resource to `false` to allow deletion.
4. The attacker may disable or modify backup configurations to prevent recovery options, such as setting backupRetentionPeriod to `0`.
5. The attacker executes the `DeleteDBInstance`, `DeleteDBCluster`, or `DeleteGlobalCluster` API call to initiate the deletion process.
6. If configured, the attacker may attempt to delete any final snapshots created during the deletion process to further hinder recovery.
7. The targeted RDS resource is permanently deleted, resulting in data loss and potential service disruption.
8. The attacker may attempt to cover their tracks by deleting relevant CloudTrail logs or modifying IAM policies.

## Impact

The deletion of RDS DB instances or clusters can lead to significant data loss, disrupting critical business operations. Depending on the size and importance of the deleted resources, organizations may face substantial financial losses, reputational damage, and regulatory penalties. If backups are unavailable or have also been compromised, data recovery may be impossible, leading to long-term business disruption. The impact can affect organizations of any size that rely on AWS RDS for data storage and retrieval.

## Recommendation

*   Deploy the Sigma rule `AWS RDS DB Instance or Cluster Deleted` to your SIEM and tune for your environment to detect unauthorized RDS resource deletions.
*   Enable deletionProtection on all critical RDS instances and clusters to prevent accidental or malicious deletion.
*   Enforce MFA for IAM users with RDS privileges to reduce the risk of compromised credentials (reference the additional information links).
*   Monitor CloudTrail logs for changes to deletionProtection settings and backup retention policies.
*   Regularly review and audit IAM policies to ensure that users and roles have only the necessary permissions.
*   Implement a process for validating unexpected RDS resource deletions with the service owner or database administrator.
*   Enable Sysmon process-creation logging to correlate with CloudTrail logs in case CLI or SDK tools are used for deletion.

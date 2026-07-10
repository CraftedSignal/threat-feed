---
title: AWS RDS Snapshot Export to S3 for Potential Data Exfiltration
slug: 2024-01-aws-rds-snapshot-exfiltration
description: An adversary may export RDS snapshots to Amazon S3 to exfiltrate sensitive data outside of RDS-managed storage, potentially bypassing database access controls and leading to unauthorized data theft.
date: "2024-01-03T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - rds
  - s3
  - exfiltration
  - cloudtrail
vendors:
  - AWS
products:
  - RDS
  - S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StartExportTask.html
  - https://attack.mitre.org/techniques/T1567/
  - https://attack.mitre.org/techniques/T1567/002/
  - https://attack.mitre.org/techniques/T1213/
  - https://attack.mitre.org/techniques/T1213/006/
rules:
  - title: AWS RDS Snapshot Export to S3
    description: Detects the export of an RDS snapshot to an S3 bucket using the StartExportTask API call, potentially indicating data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - cloudtrail
      - aws
  - title: AWS RDS Export Task with Unencrypted S3 Bucket
    description: Detects the export of an RDS snapshot to an S3 bucket without KMS encryption.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The exporting of RDS (Relational Database Service) snapshots to Amazon S3 buckets can be a legitimate operation for analytics, migration, or backup purposes. However, adversaries can abuse this functionality by exporting sensitive database snapshots to S3 buckets they control or can access, bypassing RDS's built-in security controls. This poses a significant risk of data exfiltration, as the exported snapshot is essentially a portable copy of the database contents. The activity is triggered via the `StartExportTask` API call. The scope of targeting is broad, as any organization utilizing AWS RDS is potentially vulnerable, with the impact being dependent on the sensitivity of the data stored in the RDS instances.

## Attack Chain

1.  The attacker gains unauthorized access to an AWS account with sufficient privileges to interact with RDS and S3 services. This can be achieved through compromised credentials, privilege escalation, or exploiting misconfigured IAM roles.
2.  The attacker enumerates available RDS instances and identifies those containing sensitive data using `DescribeDBSnapshots` or similar API calls.
3.  The attacker initiates a snapshot of the target RDS instance, creating a point-in-time copy of the database.
4.  The attacker calls the `StartExportTask` API to export the RDS snapshot to a specified S3 bucket. This involves specifying the snapshot identifier, the destination S3 bucket name and path, and optionally a KMS key for encryption.
5.  The exported snapshot is stored in the S3 bucket as a set of data files.
6.  The attacker configures the S3 bucket's access controls (ACLs or bucket policies) to allow access from an external AWS account or identity they control.
7.  The attacker downloads the exported snapshot files from the S3 bucket to their local system or a different cloud environment.
8.  The attacker imports the snapshot into a database instance they control, gaining access to the sensitive data contained within the RDS instance. The end objective is successful exfiltration of the database contents to a location outside the organization's control.

## Impact

Successful exploitation can lead to the exfiltration of sensitive data, including personally identifiable information (PII), financial data, or trade secrets. The number of affected victims depends on the scope of the compromised AWS environment. Organizations in highly regulated sectors like finance and healthcare are at particularly high risk. The compromise can result in significant financial losses, reputational damage, legal repercussions, and loss of customer trust.

## Recommendation

*   Deploy the Sigma rule `AWS RDS Snapshot Export to S3` to your SIEM to detect unauthorized RDS snapshot exports by monitoring `StartExportTask` events in CloudTrail logs.
*   Implement IAM least-privilege policies to restrict the ability to call `StartExportTask` to authorized users and roles only, as mentioned in the overview.
*   Continuously monitor and review S3 bucket ACLs and policies to ensure that access is restricted to authorized principals, as described in the remediation steps.
*   Enable AWS Config or Security Hub controls to monitor snapshot policy changes and alert for exports to buckets outside approved accounts, per the hardening and preventive controls advice.

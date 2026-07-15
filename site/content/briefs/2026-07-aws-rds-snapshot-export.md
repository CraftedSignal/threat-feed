---
title: AWS RDS Snapshot Export for Data Exfiltration
slug: 2026-07-aws-rds-snapshot-export
description: An adversary can leverage the AWS `rds:StartExportTask` API to export sensitive RDS database snapshots or DB cluster data to an attacker-controlled Amazon S3 bucket, facilitating data exfiltration and potential data theft from organizations.
date: "2026-07-15T14:07:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - exfiltration
  - data-theft
  - rds
  - s3
vendors:
  - Amazon
products:
  - Amazon RDS
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Identifies the export of a DB snapshot or DB cluster data to Amazon S3. Adversaries may abuse them to exfiltrate sensitive data outside of RDS-managed storage.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StartExportTask.html
rules:
  - title: AWS RDS Snapshot Export Detection
    description: Detects the export of an AWS RDS DB snapshot or DB cluster data to Amazon S3, which can be abused for data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - collection
      - exfiltration
    techniques:
      - T1213
      - T1567
      - T1567.002
    data_sources:
      - aws
      - cloudtrail
rules_count: 1
---

This threat brief describes how adversaries can abuse the legitimate AWS RDS `StartExportTask` API call to exfiltrate sensitive data. This API allows the export of an RDS DB snapshot or DB cluster data to Amazon S3, a functionality intended for analytics, migrations, or data engineering workflows. However, unauthorized use can lead to the theft of an entire database's contents, bypassing traditional database access controls. Attackers, having gained access to AWS credentials with appropriate permissions, can initiate these exports, staging sensitive information within an S3 bucket for subsequent extraction. The detection focuses on successful `StartExportTask` events, which, if unauthorized, indicate data theft, preparation for exfiltration, or a critical misconfiguration exposing regulated information such as PII, PHI, or PCI.

## Attack Chain

1. **Initial Access**: An adversary compromises AWS credentials through means such as phishing, exploiting vulnerable applications, or discovering leaked API keys.
2. **Discovery/Reconnaissance**: Using the compromised credentials, the adversary enumerates AWS RDS instances and their associated DB snapshots or DB clusters, identifying targets containing sensitive data. This might involve API calls like `DescribeDBSnapshots` or `DescribeDBClusters`.
3. **Privilege Escalation**: If the initially compromised credentials lack the necessary `rds:StartExportTask` permissions, the attacker attempts to escalate privileges to gain control over identities with the required access.
4. **Resource Provisioning**: The adversary either identifies an existing Amazon S3 bucket accessible for the export or creates a new one, potentially configuring it with specific KMS keys for encryption or public access policies to facilitate later exfiltration.
5. **Data Collection (Snapshot Export Initiation)**: The adversary initiates the `rds:StartExportTask` API call, specifying the target RDS snapshot/cluster and the S3 bucket where the data should be exported. This is the core event detected.
6. **Data Staging**: The AWS RDS service processes the request, encrypts the database contents (if specified), and writes the snapshot data into objects within the designated S3 bucket.
7. **Exfiltration from S3**: The adversary accesses the data now stored in the S3 bucket using the compromised credentials or through other means if the bucket was configured for public access, and downloads the sensitive information to an external system.
8. **Obfuscation/Evasion**: The attacker may attempt to delete or modify CloudTrail logs (though often difficult), delete the S3 bucket/objects, or modify IAM policies to conceal their activities and remove forensic evidence.

## Impact

Successful exploitation of this technique can result in severe data breaches, leading to the unauthorized disclosure of entire database contents. This includes highly sensitive information such as personally identifiable information (PII), protected health information (PHI), or payment card industry (PCI) data, which can incur significant financial penalties, regulatory fines, and reputational damage for affected organizations. Once the data is exported to an S3 bucket, it becomes portable and can be easily downloaded, shared, or transferred outside the AWS environment, making subsequent tracking and recovery extremely difficult. The primary impact is data theft, potentially affecting all data stored within the compromised RDS database.

## Recommendation

* Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect `StartExportTask` events.
* Regularly review `aws.cloudtrail` logs for all `StartExportTask` events, paying close attention to `aws.cloudtrail.user_identity.arn`, `aws.cloudtrail.user_identity.access_key_id`, `source.ip`, and `aws.cloudtrail.request_parameters`.
* Implement AWS IAM least-privilege policies to restrict `rds:StartExportTask` permissions to only authorized principals (users or roles) and ensure these permissions are rarely, if ever, assigned to general user accounts.
* Configure AWS Service Control Policies (SCPs) in production accounts to enforce stringent controls over `rds:StartExportTask` and S3 bucket access, particularly preventing exports to unapproved accounts or public buckets.
* Enable AWS CloudTrail logging for all management events across all regions and continuously monitor for suspicious API activity, including `StartExportTask` and related S3 actions.

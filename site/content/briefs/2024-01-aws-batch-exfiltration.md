---
title: AWS S3 Bucket Replication Abuse via Batch Service for Data Exfiltration
slug: 2024-01-aws-batch-exfiltration
description: Attackers can abuse the AWS Batch service to exfiltrate data from S3 buckets by creating malicious batch jobs that leverage S3 bucket replication.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - s3
  - data-exfiltration
  - batch-service
vendors:
  - AWS
products:
  - AWS S3
  - AWS Batch
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1119
    technique_name: Automated Collection
references:
  - https://hackingthe.cloud/aws/exploitation/s3-bucket-replication-exfiltration/
  - https://bleemb.medium.com/data-exfiltration-with-native-aws-s3-features-c94ae4d13436
rules:
  - title: Detect AWS Batch Job Creation for Potential S3 Exfiltration
    description: Detects the creation of AWS Batch jobs that could be used for unauthorized S3 bucket replication and data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - collection
      - exfiltration
    techniques:
      - T1119
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS Batch Job Creation from Unusual Source IP
    description: Detects the creation of AWS Batch jobs from source IPs that are not within the expected ranges.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - command_and_control
      - exfiltration
    techniques:
      - T1119
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat involves the abuse of the AWS Batch service to facilitate data exfiltration from S3 buckets. Attackers exploit the S3 bucket replication feature by creating malicious AWS Batch jobs. These jobs are designed to initiate unauthorized data transfers between S3 buckets, potentially leading to data breaches. This activity is detected through the analysis of AWS CloudTrail logs, specifically looking for `JobCreated` events and their associated details. This technique allows attackers to bypass traditional data exfiltration methods and leverage native AWS functionalities for malicious purposes. Successful exploitation can lead to significant data loss, regulatory compliance violations, and reputational damage. The scope of targeting depends on the attacker's objectives and the compromised AWS environment.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account. This could be through compromised credentials, a vulnerable application, or other means.
2. The attacker identifies a target S3 bucket containing sensitive data.
3. The attacker creates a new S3 bucket under their control or with permissive access policies in a different AWS account or region.
4. The attacker crafts a malicious AWS Batch job designed to initiate S3 bucket replication from the target bucket to the attacker-controlled bucket. This job configures the replication settings to copy the data.
5. The attacker submits the malicious AWS Batch job, triggering the replication process. The job leverages the `JobCreated` event in CloudTrail logs.
6. S3 bucket replication begins, and the data is transferred from the target bucket to the attacker's bucket.
7. Once the replication is complete, the attacker has a copy of the sensitive data in their control.
8. The attacker can then access, analyze, or further exfiltrate the data from their controlled S3 bucket.

## Impact

Successful exploitation of this technique can result in significant data loss and potential data breaches. The number of affected victims depends on the scope of the compromised AWS account and the amount of data stored in the targeted S3 buckets. Sectors that heavily rely on cloud storage, such as finance, healthcare, and government, are particularly at risk. If the attack succeeds, sensitive data, including personal information, financial records, and intellectual property, can be exposed, leading to financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Deploy the "AWS Exfiltration via Batch Service" analytic to your SIEM to detect suspicious `JobCreated` events related to S3 bucket replication (Splunk search string).
*   Implement strict IAM policies to limit the ability of users and roles to create and manage AWS Batch jobs, specifically those involving S3 bucket replication.
*   Monitor AWS CloudTrail logs for unusual S3 bucket replication configurations and job creation activities.
*   Enable and review S3 bucket access logging to detect unauthorized access and data transfers.
*   Investigate and remediate any identified `JobCreated` events with source IPs that are not within expected ranges.
*   Enforce multi-factor authentication (MFA) for all AWS accounts to prevent unauthorized access and credential compromise.

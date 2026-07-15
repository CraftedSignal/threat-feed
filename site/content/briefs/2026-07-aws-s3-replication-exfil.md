---
title: AWS S3 Bucket Replicated to External Account for Data Exfiltration
slug: 2026-07-aws-s3-replication-exfil
description: Adversaries with write access to an AWS S3 bucket can abuse replication rules via the PutBucketReplication API call to silently exfiltrate large volumes of data to attacker-controlled accounts, bypassing object-level access controls.
date: "2026-07-15T14:09:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - s3
  - exfiltration
  - threat-detection
vendors:
  - Amazon Web Services
products:
  - S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: adversaries with write access to an S3 bucket may abuse replication rules to silently exfiltrate large volumes of data to attacker-controlled accounts.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: adversaries with write access to an S3 bucket may abuse replication rules to silently exfiltrate large volumes of data to attacker-controlled accounts.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-walkthrough-2.html/
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html/
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_s3_bucket_replicated_to_external_account.toml
rules:
  - title: AWS S3 Cross-Account Replication for Exfiltration
    description: Detects the creation or modification of an S3 bucket replication configuration (PutBucketReplication) that targets a bucket in a different AWS account, a common technique for data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1537
      - T1567
      - T1567.002
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

Adversaries are known to exploit misconfigurations and compromised credentials within AWS environments to establish covert data exfiltration channels. One such technique involves the abuse of Amazon S3 cross-account replication. An attacker who has gained write access to an S3 bucket can configure a replication rule, using the `PutBucketReplication` API, to automatically copy all new or updated objects from the compromised bucket to another S3 bucket located in a different, external AWS account, which is typically under the attacker's control. This method allows for silent and continuous data exfiltration, effectively bypassing direct object-level access controls that might otherwise prevent data downloads. This tactic is particularly dangerous because once replication is configured, data flows automatically, making detection challenging without specific monitoring for configuration changes. The technique facilitates the theft of sensitive data, intellectual property, or critical logs, posing a significant risk to organizational security and compliance.

## Attack Chain

1. **Initial Access & Reconnaissance:** An attacker gains initial access to an AWS environment, often through compromised IAM credentials (e.g., access keys, console login) or exploitation of a vulnerable application. They then perform reconnaissance, using API calls like `ListBuckets` and `GetBucketPolicy`, to identify S3 buckets containing valuable data and assess their access permissions.
2. **Privilege Escalation/Lateral Movement:** The attacker leverages their initial foothold to escalate privileges or move laterally within the AWS account to obtain IAM permissions (e.g., `s3:PutBucketReplication`, `iam:PassRole`) sufficient for modifying S3 bucket replication configurations. This might involve exploiting misconfigured trust policies or assuming a compromised administrative role.
3. **Replication Role Creation/Modification:** The attacker creates a new IAM role or modifies an existing one, granting it permissions to perform S3 replication (e.g., `s3:GetObject`, `s3:ReplicateObject`, `s3:ReplicateDelete`) and establishing a trust policy that allows a principal under the attacker's control to assume this role.
4. **Configure Cross-Account Replication:** The attacker executes the `PutBucketReplication` API call against the target S3 bucket. In this request, they specify the ARN of the IAM role created/modified in the previous step and, crucially, provide their own AWS account ID as the destination for the replicated data.
5. **Silent Data Replication:** Once the `PutBucketReplication` operation is successful, any new objects uploaded to, or existing objects modified within, the source S3 bucket are automatically and silently copied to the attacker's designated S3 bucket in their external AWS account.
6. **Data Collection & Exfiltration:** The attacker accesses the exfiltrated data from their own AWS account, effectively bypassing the need for direct read or download access to the victim's S3 bucket. This continuous data flow provides the attacker with a steady stream of sensitive information.

## Impact

Successful exploitation of S3 cross-account replication leads to the unauthorized, silent, and potentially large-scale exfiltration of sensitive data to attacker-controlled infrastructure. This can include confidential business documents, personally identifiable information (PII), intellectual property, and system logs, leading to severe data breaches, regulatory fines, reputational damage, and competitive disadvantages. The stealthy nature of this technique means that data can be continuously siphoned off over extended periods before detection, making incident response more challenging and increasing the volume of compromised information. Organizations across all sectors handling sensitive data in AWS S3 buckets are at risk, with specific impact dependent on the nature and volume of the exfiltrated data.

## Recommendation

* Deploy the Sigma rule provided in this brief to your SIEM and tune it for your environment.
* Review AWS CloudTrail logs for `PutBucketReplication` events that indicate a destination `Account=` ID outside your approved AWS Organization.
* Implement AWS Service Control Policies (SCPs) to restrict cross-account S3 replication for all but explicitly approved destination accounts within your AWS Organization.
* Regularly audit IAM roles with `s3:PutBucketReplication` and `iam:PassRole` permissions to ensure they adhere to the principle of least privilege.
* Investigate `aws.cloudtrail.user_identity.arn`, `source.ip`, and `user_agent.original` fields for any `PutBucketReplication` event to identify anomalous activity.
* Rotate credentials for any IAM user or role found to be involved in unauthorized replication activity.

---
title: AWS EBS Encryption Disabled
slug: 2024-01-09-aws-ebs-encryption-disabled
description: Detects when Amazon Elastic Block Store (EBS) encryption by default is disabled in an AWS region, potentially leading to data exposure and weakening data protection against exfiltration or ransomware.
date: "2024-01-09T18:25:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - ebs
  - encryption
  - cloudtrail
vendors:
  - Amazon
products:
  - Elastic Block Store (EBS)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/disable-ebs-encryption-by-default.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html
rules:
  - title: Detect AWS EBS Encryption Disabled via CloudTrail
    description: Detects when Amazon EBS encryption by default is disabled in an AWS region using CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1565.001
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
  - title: Detect EC2 Modify Cloud Compute Configurations
    description: Detects modification of cloud compute configurations
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies instances where Amazon Elastic Block Store (EBS) encryption by default is disabled within an AWS region. The default encryption ensures that all new EBS volumes and snapshots are automatically encrypted, protecting data at rest. Disabling this setting, detected via CloudTrail logs, introduces a significant security risk.  Attackers may disable encryption to weaken data protection measures before initiating data exfiltration or tampering with EBS volumes and snapshots. This action can serve as a precursor to data theft or ransomware attacks, as unencrypted volumes are easier to compromise. The rule focuses on the `DisableEbsEncryptionByDefault` event logged by CloudTrail when this configuration change occurs. Elastic has released this rule as part of their detection ruleset on 2026-04-10.

## Attack Chain

1.  An attacker gains access to an AWS account, potentially through compromised credentials or a misconfigured IAM role.
2.  The attacker uses the AWS CLI or API to execute the `DisableEbsEncryptionByDefault` command, targeting a specific AWS region.
3.  CloudTrail logs the `DisableEbsEncryptionByDefault` event, indicating that default EBS encryption has been disabled.
4.  The attacker creates new EBS volumes within the affected region, which are now unencrypted by default.
5.  Sensitive data is stored on these newly created, unencrypted EBS volumes.
6.  The attacker exfiltrates the data from the unencrypted EBS volumes to an external location.
7.  Alternatively, the attacker might deploy ransomware on instances using the unencrypted volumes, encrypting the data and demanding a ransom.
8.  The attacker covers their tracks by deleting or modifying CloudTrail logs, if possible, to hide their activity.

## Impact

Disabling EBS encryption by default can lead to the creation of unencrypted EBS volumes, exposing sensitive data at rest. A successful attack could result in data theft, data loss, or a ransomware incident. The severity depends on the type and amount of data stored on the affected volumes. Organizations in regulated industries may face compliance violations if sensitive data is stored without encryption. This could potentially impact hundreds or thousands of EBS volumes depending on the period the encryption was disabled.

## Recommendation

*   Deploy the Sigma rule provided in this brief to detect instances of `DisableEbsEncryptionByDefault` in your AWS environment, leveraging CloudTrail logs.
*   Review IAM policies to restrict the `ec2:DisableEbsEncryptionByDefault` permission to only authorized administrators.
*   Enable AWS Config rules and Security Hub controls related to EBS encryption (`ec2-ebs-encryption-by-default-enabled`) to continuously monitor this setting, per the overview.
*   After detection, use the investigation steps in the original Elastic rule to identify affected resources and remediate the misconfiguration.
*   Enable organization-level service control policies (SCPs) to prevent future disabling of encryption-by-default across accounts, as per the original rule documentation.

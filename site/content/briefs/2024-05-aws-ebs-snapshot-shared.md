---
title: AWS EC2 EBS Snapshot Shared or Made Public
slug: 2024-05-aws-ebs-snapshot-shared
description: An AWS Elastic Block Store (EBS) snapshot is shared with another AWS account or made public, potentially leading to data exfiltration and persistence operations.
date: "2024-05-10T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - exfiltration
vendors:
  - Amazon
products:
  - Amazon EC2
  - Amazon EBS
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
references:
  - https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.html
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/aws-ebs-snapshot-dump
  - https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/
rules:
  - title: AWS EC2 EBS Snapshot Shared or Made Public
    description: Detects when an Amazon Elastic Block Store (EBS) snapshot is shared with another AWS account or made public.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 EBS Snapshot Publicly Shared
    description: Detects when an Amazon Elastic Block Store (EBS) snapshot is made publicly accessible.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This rule detects when an Amazon Elastic Block Store (EBS) snapshot is shared with another AWS account or made public. EBS snapshots contain copies of data volumes that may include sensitive or regulated information. Adversaries may exploit `ModifySnapshotAttribute` to share snapshots with external accounts or the public, allowing them to copy and access data in an environment they control. Public sharing (`group=all`) represents a severe data exposure risk, as it makes the snapshot globally readable. This activity often precedes data exfiltration or persistence operations, where the attacker transfers stolen data out of the victim account or prepares a staging area for further exploitation. The original detection rule was published on 2024/04/16 and updated on 2026/04/10.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account, potentially through compromised credentials or an exploited vulnerability.
2. The attacker identifies EBS snapshots containing sensitive data.
3. The attacker uses the `ModifySnapshotAttribute` API to modify the snapshot's permissions, adding an external AWS account or making it publicly accessible (`group=all`).
4. The attacker may also disable EBS encryption to facilitate easier access to the data.
5. The external AWS account copies the shared snapshot using `CopySnapshot`.
6. The copied snapshot is then mounted as a volume on an EC2 instance within the attacker's AWS account.
7. The attacker accesses and exfiltrates the sensitive data from the mounted volume.
8. The attacker may then cover their tracks by deleting the copied snapshot and associated resources in their account.

## Impact

Compromise of EBS snapshots can lead to the exfiltration of sensitive data, including personally identifiable information (PII), financial records, and proprietary business data. A successful attack could result in regulatory fines, reputational damage, and financial losses. Sharing snapshots publicly can expose data to a wide range of malicious actors, increasing the risk of unauthorized access and misuse. The number of affected snapshots and the sensitivity of the contained data determine the magnitude of the impact.

## Recommendation

*   Deploy the Sigma rule "AWS EC2 EBS Snapshot Shared or Made Public" to your SIEM and tune for your environment, focusing on `ModifySnapshotAttribute` events (see rules section).
*   Review `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` to identify who modified the snapshot’s permissions. Evaluate whether this identity is authorized to share EBS snapshots, as described in the overview section.
*   Restrict `ec2:ModifySnapshotAttribute` permissions to trusted administrative roles only and enforce multi-factor authentication (MFA) for these accounts, as described in the overview section.
*   Enable AWS Config rules such as `ebs-snapshot-public-restorable-check` to continuously monitor for public EBS snapshots, as described in the overview section.

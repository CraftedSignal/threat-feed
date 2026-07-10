---
title: AWS EFS File System Deletion Detected
slug: 2024-01-aws-efs-deletion
description: An adversary with sufficient permissions deletes an Amazon EFS file system using the 'DeleteFileSystem' API operation to destroy evidence, disrupt workloads, or impede recovery efforts.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - efs
  - data-destruction
  - impact
vendors:
  - AWS
products:
  - Elastic File System (EFS)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html
  - https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.html
  - https://attack.mitre.org/techniques/T1485/
rules:
  - title: AWS EFS File System Deleted
    description: Detects the deletion of an Amazon EFS file system using the DeleteFileSystem API operation.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS EFS Mount Target Deleted
    description: Detects deletion of an EFS mount target, which is often done before deleting the file system.
    platform: sigma
    severity: informational
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

The Amazon Elastic File System (EFS) provides scalable, shared file storage. The deletion of an EFS file system, detected via the "DeleteFileSystem" API operation, permanently removes all stored data, which cannot be recovered. This action is rare outside of controlled teardown workflows. This event, logged by AWS CloudTrail, can signal intentional data destruction, preparation for ransomware attacks, or post-compromise cleanup activities. The rule focuses exclusively on the irreversible destructive event of deleting an EFS file system via the `DeleteFileSystem` API call. Detection is based on logs from `elasticfilesystem.amazonaws.com`.

## Attack Chain

1.  Adversary gains unauthorized access to an AWS account.
2.  The adversary escalates privileges within the AWS account to obtain permissions to delete EFS file systems.
3.  Adversary enumerates existing EFS file systems using AWS CLI or API calls.
4.  Adversary identifies a target EFS file system for deletion.
5.  Adversary deletes mount targets associated with the EFS file system.
6.  Adversary executes the `DeleteFileSystem` API call via AWS CLI, API, or console.
7.  The EFS file system and its stored data are permanently deleted.
8.  Adversary may attempt to delete CloudWatch logs to remove traces of their activity.

## Impact

The deletion of an EFS file system results in permanent data loss, disrupting workloads reliant on the deleted file system. This can lead to significant operational downtime, financial losses, and potential compliance violations, especially if the file system contained sensitive or regulated data. The impact varies based on the importance of the data and the availability of backups. Recovering from this requires restoring from backups, if available, or rebuilding the infrastructure and data from scratch.

## Recommendation

*   Deploy the Sigma rule "AWS EFS File System Deleted" to your SIEM and tune for your environment to detect unauthorized deletions of EFS file systems.
*   Restrict the use of `elasticfilesystem:DeleteFileSystem` to tightly controlled IAM roles as mentioned in the overview section.
*   Review `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` to identify the actor and calling context as described in the Triage section of the documentation.
*   Ensure AWS Backup policies include EFS resources with sufficient retention to mitigate data loss from accidental or malicious deletion.
*   Use AWS Config or Security Hub controls to detect EFS file systems without backup plans as described in the Hardening section.

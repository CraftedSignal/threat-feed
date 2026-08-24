---
title: Monitoring Unauthorized Amazon EFS File System Deletion
slug: 2026-08-aws-efs-deletion
description: Adversaries with high-privilege access can leverage the DeleteFileSystem API to permanently destroy data, disrupt cloud-native applications, or remove forensic evidence.
date: "2026-08-24T09:49:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - impact
  - aws
  - data-destruction
vendors:
  - Amazon
products:
  - Elastic File System
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Deleting an EFS file system permanently removes all stored data and cannot be reversed.
    confidence_band: high
rules:
  - title: Detect Unauthorized AWS EFS File System Deletion
    description: Detects successful execution of the DeleteFileSystem API operation, which is a high-impact destructive action. Filtered to exclude common IaC tooling.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloud_api
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the EFS deletion detection rule to SIEM environment.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in official detection-rules repository.
  mitigation_plan:
    - priority: immediate
      action: Restrict DeleteFileSystem permissions via IAM policy.
      owner: IT Operations
      addresses: T1485
      evidence: Security Best Practices documented in source.
---

The deletion of an Amazon Elastic File System (EFS) via the `DeleteFileSystem` API is an irreversible operation that permanently removes all stored data. While legitimate lifecycle management and teardown workflows utilize this API, adversaries who have compromised cloud credentials can exploit this functionality to perform intentional data destruction, disrupt business operations, or engage in anti-forensic cleanup to impede incident response. 

Defenders must differentiate between authorized automated infrastructure-as-code (IaC) workflows - typically originating from known service roles or CI/CD pipelines - and unauthorized manual invocations of this API. This threat is particularly critical for production environments where EFS provides shared storage for persistent applications, container workloads, and analytics pipelines. Monitoring for this event in CloudTrail is essential for detecting post-compromise activity or malicious preparation for ransomware scenarios.

## Impact

Successful unauthorized execution of `DeleteFileSystem` results in total loss of stored file system data. This can cause immediate service disruption for dependent EC2 instances, ECS tasks, and serverless compute workloads. Depending on the organization's backup configuration, data may not be recoverable if AWS Backup policies were either absent or intentionally disabled by the attacker prior to the deletion event.

## Recommendation

* Deploy the provided Sigma-compatible detection logic to SIEM platforms to monitor for `DeleteFileSystem` events, ensuring filters are tuned to ignore known CI/CD automation principals (e.g., Terraform, Pulumi).
* Restrict the `elasticfilesystem:DeleteFileSystem` IAM permission to specific, highly privileged administrative roles and implement condition keys such as `aws:SourceIp` or `aws:PrincipalArn` to prevent unauthorized execution.
* Enable AWS Backup for all production EFS file systems and monitor for modifications to backup plans using AWS Config or Security Hub to ensure data remains recoverable.
* Use CloudTrail alerts to notify the Security Operations Center (SOC) of any `DeleteFileSystem` events occurring outside of established change windows or from unusual IP addresses.

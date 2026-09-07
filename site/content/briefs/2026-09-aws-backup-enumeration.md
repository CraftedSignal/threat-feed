---
title: Detection of AWS Backup Resource Enumeration via Long-Term Access Keys
slug: 2026-09-aws-backup-enumeration
description: Adversaries may use compromised long-term IAM access keys (AKIA* prefix) to enumerate AWS Backup vaults, plans, and protected resources as a precursor to ransomware activities.
date: "2026-09-07T10:42:40Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - discovery
  - ransomware
vendors:
  - Amazon
products:
  - AWS Backup
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
    evidence: Adversaries performing ransomware preparation systematically enumerate backup vaults to locate recovery points, assess vault lock configuration, and identify which vaults can be deleted.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ListBackupVaults.html
  - https://hackingthe.cloud/aws/enumeration/enumerate_services_via_aws_backup/
rules:
  - title: Detect AWS Backup Resource Enumeration
    description: Detects enumeration of AWS Backup resources using long-term IAM access keys (AKIA* prefix)
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule for AWS Backup enumeration.
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief.
  mitigation_plan:
    - priority: immediate
      action: Identify all IAM users utilizing long-term AKIA keys and migrate to temporary credentials.
      owner: IT Operations
      addresses: Security anti-pattern identified in brief.
---

Adversaries are utilizing compromised long-term IAM access keys (identifiable by the AKIA* prefix) to perform reconnaissance against AWS Backup environments. This activity allows threat actors to map backup vaults, plans, and protected resources, including EC2 instances, EBS volumes, RDS databases, DynamoDB tables, and S3 buckets. 

This reconnaissance is typically a precursor to ransomware, where the objective is to locate recovery points, assess the presence of Vault Lock configurations, and determine which backup resources can be deleted or disabled. By identifying and neutralizing backup capabilities before encrypting primary data stores, adversaries significantly increase the likelihood of extortion success. The use of long-term access keys for such management tasks is considered a security anti-pattern, as these tasks are typically handled by temporary credentials or automated roles. Monitoring for these specific API calls originating from static access keys is critical for identifying potential ransomware preparation in cloud environments.

## Attack Chain

1. An adversary obtains long-term IAM access keys (AKIA*) through credential exposure in CI/CD pipelines, source code, or configuration files.
2. The adversary authenticates to the AWS environment using the compromised static access key.
3. The adversary initiates discovery calls such as ListBackupVaults and ListBackupPlans to map the organization's backup architecture.
4. The adversary identifies protected resources and recovery points using calls like ListProtectedResources and DescribeRecoveryPoint.
5. The adversary assesses vault access policies and protections using GetBackupVaultAccessPolicy and GetBackupVaultLockConfiguration to identify targets for deletion.
6. The adversary potentially modifies or deletes backup vaults, plans, or recovery points to eliminate recovery options.
7. The adversary proceeds to encrypt the primary data stores (e.g., S3, RDS, EC2/EBS), knowing that backups are unavailable or compromised.

## Impact

Successful exploitation allows adversaries to systematically degrade or destroy an organization's disaster recovery capabilities. By identifying high-value data backed up in specific vaults and bypassing or removing backup protections, threat actors ensure that the primary data encryption phase of a ransomware attack cannot be remediated via standard recovery processes.

## Recommendation

- Immediately deactivate any long-term IAM access keys observed performing backup enumeration from unauthorized IP addresses.
- Enable AWS Backup Vault Lock (WORM) on critical backup vaults to ensure recovery points cannot be deleted during a set compliance period.
- Implement a policy to migrate all administrative and backup management automation from long-term static keys to short-lived credentials via IAM roles.
- Monitor CloudTrail logs for unexpected usage of backup management API actions by non-privileged IAM users.
- Utilize the Sigma rule below to detect this reconnaissance behavior in your SIEM environment.

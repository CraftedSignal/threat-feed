---
title: Detection of Unauthorized Amazon RDS Instance and Cluster Deletion
slug: 2026-08-aws-rds-deletion
description: Adversaries with compromised credentials may delete Amazon RDS DB instances or Aurora clusters to cause permanent data loss, disrupt operations, or destroy forensic evidence.
date: "2026-08-24T09:50:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - impact
  - aws
  - cloud-security
vendors:
  - Amazon
products:
  - Amazon RDS
  - Amazon Aurora
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries may delete RDS resources as part of a destructive attack, to eliminate forensic evidence, or to disrupt critical workloads.
    confidence_band: high
rules:
  - title: AWS RDS DB Instance or Cluster Deleted
    description: Detects the deletion of an Amazon RDS DB instance, Aurora cluster, or global database cluster, which may indicate malicious destructive activity.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Review all RDS deletion events in CloudTrail for the last 30 days to identify unauthorized activity
      owner: SOC
      due: 48h
      evidence: Rule provided detects deletion events requiring investigation
  mitigation_plan:
    - priority: immediate
      action: Enable deletionProtection on all mission-critical production RDS instances
      owner: IT Operations
      addresses: T1485
      evidence: Recommended hardening action in the source material
---

This threat brief focuses on the unauthorized deletion of Amazon RDS resources, including DB instances, Aurora clusters, and global database clusters. Threat actors may target these resources to achieve a permanent Impact objective, causing significant service disruption and data loss. This activity is typically performed via AWS API calls, specifically 'DeleteDBInstance', 'DeleteDBCluster', and 'DeleteGlobalCluster'. 

Attackers often prepare for this destructive action by first modifying safety controls, such as disabling 'deletionProtection' or reducing the 'backupRetentionPeriod' to zero, ensuring that recovery options are minimized or eliminated before the final deletion command is issued. Defenders must monitor CloudTrail for these administrative actions, particularly when they deviate from established infrastructure-as-code (IaC) deployment patterns like Terraform or Pulumi. Success in this attack leads to immediate data unavailability and complicates forensic investigations by removing the state of the database and associated audit logs.

## Attack Chain

1. Initial access is gained through compromised IAM credentials or a leaked access key (T1078).
2. The attacker performs reconnaissance of RDS resource configurations and associated IAM policies.
3. The attacker disables 'deletionProtection' on critical RDS instances or clusters to permit deletion.
4. The attacker modifies the 'backupRetentionPeriod' to zero to prevent point-in-time recovery.
5. The attacker optionally deletes existing manual snapshots to ensure no alternative recovery path exists.
6. The attacker invokes 'DeleteDBInstance', 'DeleteDBCluster', or 'DeleteGlobalCluster' API actions.
7. The database resource is destroyed, resulting in permanent data loss and service disruption.

## Impact

Successful execution of these destructive API calls results in the immediate and permanent deletion of RDS database resources. This leads to severe business service disruption, the potential loss of entire customer datasets, and the destruction of evidence that could be used for incident response and root-cause analysis. Organizations without off-site or immutable backups for these databases face prolonged downtime and significant data recovery challenges.

## Recommendation

- Deploy detection for RDS deletion events to identify unauthorized destructive API calls, excluding known automation service principals.
- Implement 'deletionProtection' on all production RDS instances and Aurora clusters to prevent accidental or malicious deletion.
- Enforce Multi-Factor Authentication (MFA) for any IAM role or user possessing permissions to perform 'rds:Delete*' operations.
- Audit existing IAM policies to apply the principle of least privilege, ensuring only authorized administrative roles can execute RDS modification or deletion commands.
- Establish a process for verifying that the 'DeleteDBInstance' or 'DeleteDBCluster' actions are associated with authorized decommissioning or legitimate IaC workflows.

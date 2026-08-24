---
title: AWS RDS Deletion Protection Disabled
slug: 2026-08-aws-rds-deletion-protection
description: Adversaries with elevated IAM permissions may disable deletion protection on AWS RDS instances or clusters as a prerequisite for unauthorized data destruction.
date: "2026-08-24T09:50:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - rds
  - impact
  - defense-evasion
vendors:
  - Amazon
products:
  - RDS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries with sufficient permissions may disable this protection as a precursor to destructive actions, including the deletion of databases containing sensitive or business-critical data.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: This rule alerts when deletionProtection is explicitly set to false on an RDS DB instance or cluster.
    confidence_band: high
rules:
  - title: Detect AWS RDS Deletion Protection Disabled
    description: Detects unauthorized modification of AWS RDS DB instance or cluster to disable the deletionProtection feature, a precursor to data destruction.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
      - T1578.005
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule provides visibility into unauthorized modification of security safeguards.
  hunt_leads:
    - lead: Identify all instances of ModifyDBInstance or ModifyDBCluster where deletionProtection was set to false over the last 90 days.
      technique_id: T1578.005
      data_needed:
        - CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Historical review helps identify potential prior unauthorized changes.
  mitigation_plan:
    - priority: immediate
      action: Implement IAM SCPs to prevent unauthorized modification of RDS deletion protection.
      owner: IT Operations
      addresses: T1578.005
      evidence: Restriction of API permissions limits the attacker's ability to lower defenses.
---

This threat brief addresses the unauthorized modification of AWS RDS DB instances or clusters to disable the deletionProtection feature. Deletion protection is a security safeguard intended to prevent accidental or malicious deletion of database resources. Attackers who have obtained sufficient IAM permissions to modify cloud compute infrastructure often target this setting as a deliberate precursor to destructive activities, such as the total deletion of databases containing sensitive or business-critical information. Monitoring for the explicit removal of this safeguard provides a critical detection window for incident responders to intervene before data loss occurs. Defenders should distinguish between legitimate infrastructure-as-code deployments and interactive manual modifications by unauthorized users.

## Attack Chain

1. Attacker gains persistence or elevates privileges within the AWS environment via compromised IAM credentials.
2. Attacker performs reconnaissance to identify high-value RDS instances and clusters using `DescribeDBInstances` or `DescribeDBClusters`.
3. Attacker checks the current configuration of the target RDS instance to confirm the state of `deletionProtection`.
4. Attacker executes `ModifyDBInstance` or `ModifyDBCluster` API calls with the `deletionProtection=false` parameter to remove the safeguard.
5. Attacker performs secondary destructive actions, such as disabling automated backups or snapshots to hinder recovery.
6. Attacker issues `DeleteDBInstance` or `DeleteDBCluster` commands to destroy the target database and impact availability.

## Impact

Successful exploitation allows for the permanent deletion of mission-critical production databases. If an attacker disables deletion protection and subsequently deletes the database, the organization faces significant data loss, service outages, and potential regulatory non-compliance, depending on the nature of the data stored within the impacted RDS environment.

## Recommendation

- Deploy the Sigma rule below to monitor CloudTrail for suspicious modifications to RDS deletion protection settings.
- Implement AWS Service Control Policies (SCPs) or IAM condition keys to restrict the ability of non-admin roles to modify `deletionProtection`.
- Review historical CloudTrail logs for accounts where `ModifyDBInstance` or `ModifyDBCluster` occurred with `deletionProtection=false` to identify potential prior unauthorized access.
- Establish an alerting workflow for `DeleteDBInstance` and `DeleteDBCluster` events to quickly identify and respond to attempted data destruction.

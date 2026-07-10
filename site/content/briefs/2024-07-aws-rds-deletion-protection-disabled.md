---
title: AWS RDS DB Instance or Cluster Deletion Protection Disabled
slug: 2024-07-aws-rds-deletion-protection-disabled
description: An adversary may disable deletion protection on an AWS RDS DB instance or cluster as a precursor to destructive actions, such as deleting databases containing sensitive data.
date: "2024-07-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - rds
  - datadestruction
vendors:
  - AWS
products:
  - AWS RDS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html
rules:
  - title: AWS RDS Deletion Protection Disabled via CloudTrail
    description: Detects when deletion protection is disabled on an AWS RDS DB instance or cluster via CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
  - title: AWS RDS Instance Deletion via CloudTrail
    description: Detects when an AWS RDS DB instance is deleted via CloudTrail logs.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This alert identifies instances where the deletionProtection feature of an AWS RDS DB instance or cluster is disabled. Deletion protection is a security mechanism that prevents accidental or unauthorized deletion of RDS resources. An adversary with sufficient permissions within a compromised AWS environment may disable this protection to pave the way for destructive activities, including the deletion of databases that hold sensitive or business-critical information. The detection focuses on explicit modifications setting `deletionProtection` to `false` on RDS DB instances or clusters. This activity is often a precursor to a `DeleteDBInstance` or `DeleteDBCluster` action.

## Attack Chain

1.  The adversary gains access to an AWS account with sufficient privileges to modify RDS instances or clusters, potentially through compromised credentials or an insider threat.
2.  The attacker authenticates to the AWS Management Console, CLI, or API using the compromised credentials or assumed role.
3.  The attacker uses the `ModifyDBInstance` or `ModifyDBCluster` API call to target a specific RDS DB instance or cluster.
4.  Within the `ModifyDBInstance` or `ModifyDBCluster` API call, the attacker sets the `deletionProtection` parameter to `false`.
5.  AWS CloudTrail logs the `ModifyDBInstance` or `ModifyDBCluster` event with `deletionProtection=false` in the `requestParameters`.
6.  The attacker may then initiate a `DeleteDBInstance` or `DeleteDBCluster` API call to remove the targeted RDS resource.
7.  The database instance or cluster is deleted, resulting in data loss and potential disruption of services.

## Impact

Disabling deletion protection on AWS RDS instances or clusters can lead to the unauthorized or accidental deletion of critical databases. Successful execution of this attack can result in significant data loss, business disruption, and potential financial repercussions. The impact can range from temporary service outages to permanent data loss, depending on the affected systems and backup policies.

## Recommendation

*   Deploy the Sigma rule `AWS RDS Deletion Protection Disabled via CloudTrail` to your SIEM and tune for your environment to detect when deletion protection is disabled (refer to the rule definition below).
*   Review `aws.cloudtrail.user_identity.arn` to determine the IAM principal that made the change, and validate whether this principal normally performs RDS lifecycle operations as outlined in the investigation guide.
*   Immediately re-enable deletion protection (`deletionProtection=true`) on the affected DB instance or cluster if the change was unauthorized, as described in the remediation steps in the overview.
*   Restrict who can modify `ModifyDBInstance` or `ModifyDBCluster` destructive settings, such as deletion protection, backup retention, and public accessibility.

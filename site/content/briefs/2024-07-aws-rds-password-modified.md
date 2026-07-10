---
title: AWS RDS DB Instance or Cluster Password Modification
slug: 2024-07-aws-rds-password-modified
description: The modification of the master password for an AWS RDS DB instance or cluster can indicate malicious activity used for persistence, privilege escalation, or defense evasion.
date: "2024-07-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - rds
  - persistence
vendors:
  - AWS
products:
  - RDS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-rds-privesc#rds-modifydbinstance
rules:
  - title: AWS RDS DB Instance or Cluster Password Modified
    description: Detects modification of the master password for an AWS RDS DB instance or cluster.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
  - title: AWS RDS DB Instance Manage Master User Password Disabled
    description: Detects the disabling of manageMasterUserPassword on AWS RDS DB Instances or Clusters, potentially indicating an attempt to bypass Secrets Manager integration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on the modification of master passwords for AWS RDS DB instances or clusters. While password changes can be legitimate for recovery actions, attackers with sufficient permissions can exploit this to regain access, establish persistence, bypass existing controls, or escalate privileges within a compromised environment. The primary concern arises because RDS does not expose passwords in API responses, making any such modification a meaningful change to access pathways, potentially impacting sensitive data stores. This activity is detected via `ModifyDBInstance` or `ModifyDBCluster` events in AWS CloudTrail.

## Attack Chain

1. An attacker gains initial access to an AWS account through compromised credentials, exploiting a vulnerable application, or other means.
2. The attacker enumerates existing RDS DB instances and clusters using AWS CLI or API calls, such as `DescribeDBInstances`.
3. The attacker identifies a target RDS DB instance or cluster containing sensitive data or critical functionality.
4. The attacker executes `ModifyDBInstance` or `ModifyDBCluster` via the AWS CLI or API, changing the master user password. This requires appropriate IAM permissions.
5. The attacker uses the newly modified password to authenticate to the database and gain privileged access.
6. The attacker performs malicious actions within the database, such as exfiltrating data, modifying data, or creating new accounts with elevated privileges.
7. The attacker may disable deletion protection or modify backup retention policies to further ensure persistence or cover their tracks.

## Impact

Successful modification of RDS master passwords can lead to significant data breaches, service disruption, and financial losses. While specific victim numbers and sectors aren't available, the impact of a compromised RDS instance can be severe. If an attacker successfully modifies the password, they can gain complete control over the database, potentially leading to the exfiltration of sensitive information, modification or deletion of critical data, and the compromise of applications relying on the database.

## Recommendation

*   Deploy the Sigma rule "AWS RDS DB Instance or Cluster Password Modified" to detect unauthorized password modifications (rule).
*   Review `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` in AWS CloudTrail logs to identify the source of password modification events (log source).
*   Limit IAM permissions for `rds:ModifyDBInstance` and `rds:ModifyDBCluster`, especially when modifying authentication parameters (reference).
*   Implement multi-factor authentication (MFA) and role-based access control (RBAC) for DB administrators (reference).

---
title: Detection of Unauthorized AWS RDS Instance Restoration
slug: 2026-09-aws-rds-restore
description: Threat actors with compromised AWS credentials may use RDS restoration operations to duplicate sensitive database environments, facilitating unauthorized data access, staging, and exfiltration while bypassing production monitoring controls.
date: "2026-09-18T19:27:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - defense-evasion
  - collection
  - aws
vendors:
  - Amazon
products:
  - Relational Database Service (RDS)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: Adversaries with access to valid credentials may restore copies of existing databases to bypass logging and monitoring controls or to exfiltrate sensitive data from a duplicated environment.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: This rule detects successful restoration operations using RestoreDBInstanceFromDBSnapshot or RestoreDBInstanceFromS3, which may indicate unauthorized data access or post-compromise defense evasion.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
    evidence: Adversaries may use restore actions to access historical data, duplicate sensitive environments, evade guardrails, or prepare for data exfiltration.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromDBSnapshot.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_RestoreDBInstanceFromS3.html
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-rds-post-exploitation
rules:
  - title: Detect Unauthorized AWS RDS Instance Restoration
    description: Detects successful execution of RestoreDBInstanceFromDBSnapshot or RestoreDBInstanceFromS3, which may indicate unauthorized database duplication for data staging or evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1578.002
      - T1578.004
    data_sources:
      - webserver
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule for RDS restoration monitoring.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides detection query for unauthorized RDS restoration.
  hunt_leads:
    - lead: Search for instances restored by non-authorized IAM principals or outside of planned maintenance windows.
      technique_id: T1578.002
      data_needed:
        - CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries may use restore actions to access historical data.
  mitigation_plan:
    - priority: immediate
      action: Enforce least privilege IAM policies for RDS restoration permissions.
      owner: IT Operations
      addresses: T1578
      evidence: Enforce least privilege for rds:RestoreDBInstanceFromDBSnapshot and rds:RestoreDBInstanceFromS3.
---

Adversaries possessing valid AWS credentials can exploit the RDS restoration functionality to rehydrate database snapshots or S3-based backups into new instances. By creating a duplicate environment, attackers can bypass production-level logging, security guardrails, or deletion protection to access historical, sensitive, or supposedly deleted data. This technique is often used for staging data for exfiltration or establishing shadow environments for persistent malicious operations. Because this action involves legitimate API calls, defenders must distinguish between standard administrative maintenance - such as disaster recovery drills, patch testing, or automated CI/CD migrations - and anomalous restoration requests that originate from unexpected IAM principals, unusual source IP addresses, or occur without an associated change management record.

## Impact

Successful exploitation allows attackers to gain unauthorized access to sensitive datasets, potentially leading to large-scale data exfiltration. Furthermore, by creating an isolated or shadow database environment, an attacker can perform intensive data analysis or dumps without triggering alerts tied to the production database's performance metrics or audit logs. This may expose organizations to significant compliance violations and loss of intellectual property.

## Recommendation

- Implement the detection rule below to monitor for `RestoreDBInstanceFromDBSnapshot` and `RestoreDBInstanceFromS3` API calls in CloudTrail.
- Establish an alert triage process that cross-references RDS restoration events with change management systems, automation account signatures, and authorized user identity ARNs.
- Apply the principle of least privilege to IAM roles; restrict the ability to perform `rds:RestoreDBInstanceFromDBSnapshot` and `rds:RestoreDBInstanceFromS3` to specific, authorized principals and networks using IAM condition keys.
- Monitor AWS Config and Security Hub for the creation of publicly accessible RDS instances or instances with non-compliant security group configurations.
- Review CloudTrail logs for associated post-compromise activity, including unauthorized snapshot exports, cross-account permissions modifications, or the deletion of the original database instance.

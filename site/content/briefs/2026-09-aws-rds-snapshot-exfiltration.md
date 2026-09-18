---
title: AWS RDS Database Snapshot Unauthorized External Sharing
slug: 2026-09-aws-rds-snapshot-exfiltration
description: Adversaries may exfiltrate sensitive data from AWS RDS by modifying snapshot attributes to share them with an external, attacker-controlled AWS account, enabling unauthorized offline access to the database content.
date: "2026-09-18T19:32:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - exfiltration
  - aws
  - rds
vendors:
  - Amazon
products:
  - Amazon RDS
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Adversaries may abuse this mechanism for stealthy data exfiltration, restoring the snapshot in infrastructure they control, outside of your monitoring boundary.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_rds_snapshot_shared_with_another_account.toml
  - https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBSnapshotAttribute.html
  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html
  - https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-rds-post-exploitation#rds-modifydbsnapshotattribute-rds-createdbsnapshot
rules:
  - title: Detect AWS RDS DB Snapshot Shared with Another Account
    description: Detects unauthorized modification of RDS DB snapshot attributes to share with external AWS accounts, a technique used for data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - cloudtrail
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Deploy the detection rule to identify cross-account snapshot sharing.
      owner: Detection Engineering
      due: 48h
      evidence: Rule targets ModifyDBSnapshotAttribute actions explicitly.
  hunt_leads:
    - lead: Identify all snapshot sharing events occurring within the last 30 days.
      technique_id: T1537
      data_needed:
        - CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source states that adversaries use this mechanism for data exfiltration.
  mitigation_plan:
    - priority: immediate
      action: Enforce SCPs to restrict snapshot sharing to authorized accounts only.
      owner: Cloud Security
      addresses: Unauthorized snapshot sharing
      evidence: Source mentions SCPs as a preventive control.
---

Adversaries who obtain valid AWS credentials or exploit misconfigurations may abuse the RDS database snapshot sharing mechanism to perform stealthy data exfiltration. By modifying a snapshot's restore attributes using the `ModifyDBSnapshotAttribute` or `ModifyDBClusterSnapshotAttribute` API calls, an attacker can grant an external, attacker-controlled AWS account permission to restore and access the database. Because these snapshots contain complete backups including schemas, sensitive application data, and credentials, sharing them externally bypasses standard network and IAM monitoring controls, as the data extraction occurs in an environment outside the victim's visibility. This technique is particularly effective for large-scale exfiltration, as it allows attackers to analyze the data offline.

## Impact

Successful exploitation results in the unauthorized exposure of sensitive database content, including PII, customer data, and internal credentials. Once an external account gains restore permissions, the data is essentially exfiltrated, leading to potential regulatory non-compliance, loss of intellectual property, and increased risk of follow-on attacks using recovered credentials.

## Recommendation

Prioritize the implementation of detective and preventive controls to limit cross-account snapshot exposure.

- Deploy the detection rules provided below to monitor CloudTrail for `ModifyDBSnapshotAttribute` and `ModifyDBClusterSnapshotAttribute` events.
- Implement AWS Organizations Service Control Policies (SCPs) to strictly prohibit or restrict cross-account snapshot sharing to a known-safe list of accounts.
- Utilize IAM condition keys (e.g., `kms:ViaService`, `rds:dbSnapshotArn`) to enforce strict policies on who can modify snapshot permissions.
- Configure AWS Security Hub and Config rules to alert on publicly shared snapshots or snapshots shared with unauthorized external account IDs.

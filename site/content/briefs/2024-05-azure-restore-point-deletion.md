---
title: Azure Compute Restore Point Collections Mass Deletion
slug: 2024-05-azure-restore-point-deletion
description: A single user deleting multiple Azure Restore Point Collections in a short time period can indicate a ransomware attack or destructive operation, preventing victim recovery by inhibiting system recovery.
date: "2024-05-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - cloud
  - ransomware
  - impact
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://www.microsoft.com/en-us/security/blog/2023/07/25/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/
rules:
  - title: Azure Multiple Restore Point Collection Deletions
    description: Detects multiple Azure Restore Point Collections being deleted by a single user in a short period.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure Restore Point Collection Deletion by Non-Admin
    description: Detects Restore Point Collection deletions by users without administrative roles.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - cloudtrail
      - azure
      - activitylog
rules_count: 2
---

This alert identifies the rapid deletion of multiple Azure Restore Point Collections. Restore Point Collections contain recovery points for virtual machines, providing essential point-in-time recovery capabilities. Adversaries often target these collections during ransomware attacks to prevent victims from recovering their systems. Mass deletion, defined here as more than 3 deletions by a single user, within a short timeframe is a strong indicator of malicious activity aimed at disabling recovery options. The rule leverages Azure Activity Logs to detect this behavior and is applicable to any Azure environment utilizing Restore Point Collections.

## Attack Chain

1. Initial access is gained through compromised credentials or an insider threat.
2. The attacker enumerates existing Azure Restore Point Collections within the subscription.
3. The attacker attempts to escalate privileges if necessary, to gain sufficient permissions to delete the restore point collections.
4. The attacker initiates the deletion of multiple Restore Point Collections in rapid succession.
5. Azure Activity Logs record the DELETE operations on the Restore Point Collections, including the user identity and resource IDs.
6. The attacker may delete virtual machines and disks to maximize damage and hinder recovery efforts.
7. Backups and recovery services may also be targeted for deletion.
8. The attacker achieves the objective of preventing system recovery, potentially leading to data loss and operational disruption.

## Impact

Successful deletion of Azure Restore Point Collections can severely impact an organization's ability to recover from ransomware attacks or other destructive events. The inability to restore VMs from backups can lead to prolonged downtime, data loss, and significant financial repercussions. Organizations may face regulatory fines, reputational damage, and loss of customer trust. The scope of the impact depends on the criticality of the VMs protected by the deleted restore points.

## Recommendation

*   Deploy the Sigma rule provided to your SIEM and tune the threshold (currently 3 deletions) for your environment based on normal administrative activity.
*   Investigate any alerts triggered by the Sigma rule, focusing on identifying the user account involved and the scope of the deletions.
*   Review and strengthen access controls for Restore Point Collection management, implementing stricter RBAC policies and requiring multi-factor authentication for privileged operations.
*   Implement Azure Resource Locks on critical recovery resources to prevent accidental or malicious deletion.
*   Monitor Azure Activity Logs for related activities such as deletion of Recovery Services resources and modifications to backup policies.
*   Consult the included references for information about threat actors targeting cloud environments.

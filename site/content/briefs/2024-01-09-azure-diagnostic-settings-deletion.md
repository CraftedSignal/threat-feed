---
title: Azure Diagnostic Settings Deletion for Defense Evasion
slug: 2024-01-09-azure-diagnostic-settings-deletion
description: Adversaries may delete Azure diagnostic settings to evade defenses by hindering detection and analysis, which this detection identifies by monitoring Azure activity logs for successful deletion operations.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - defense_evasion
  - cloud
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings
  - https://www.microsoft.com/en-us/security/blog/2025/10/20/inside-the-attack-chain-threat-activity-targeting-azure-blob-storage/
rules:
  - title: Azure Diagnostic Settings Deleted
    description: Detects the deletion of diagnostic settings in Azure Activity Logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.008
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Azure Diagnostic Settings Deletion Attempt (Failed)
    description: Detects failed attempts to delete diagnostic settings in Azure Activity Logs, which may indicate reconnaissance or privilege escalation attempts.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.008
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

Azure diagnostic settings are crucial for monitoring and logging platform activities, sending data to various destinations for analysis. Adversaries may delete these settings in an attempt to evade defenses by hindering detection and analysis of their activities. The detection rule identifies such deletions by monitoring specific Azure activity logs for successful deletion operations, flagging potential defense evasion attempts. This activity can be part of a larger attack chain where the adversary aims to operate undetected within the Azure environment. The targeted deletion of diagnostic settings impacts security monitoring capabilities across the targeted resources, reducing visibility for defenders.

## Attack Chain

1.  The attacker gains initial access to the Azure environment, potentially through compromised credentials or exploiting a vulnerability in a deployed application.
2.  The attacker enumerates existing diagnostic settings within the target Azure subscription or resource group.
3.  The attacker identifies diagnostic settings associated with critical resources or log sources that would expose their activity.
4.  The attacker uses an account with sufficient privileges (e.g., Owner, Contributor, or custom role with "Microsoft.Insights/diagnosticSettings/write" permission) to initiate the deletion of diagnostic settings.
5.  The Azure Activity Log records an event with `operation_name` equal to `MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE` and `event.outcome` as `Success`.
6.  The diagnostic settings are removed, stopping the flow of logs and metrics to configured destinations (e.g., Log Analytics workspace, storage account, event hub).
7.  The attacker continues their malicious activities within the Azure environment, now with reduced risk of detection due to the disabled logging.

## Impact

Successful deletion of Azure diagnostic settings severely impairs an organization's ability to detect and respond to malicious activity within their Azure environment. The loss of logging data can prevent security teams from identifying breaches, investigating incidents, and performing effective threat hunting. The impact extends across all sectors utilizing Azure services. A successful attack could result in data breaches, system compromise, and financial losses.

## Recommendation

*   Deploy the Sigma rule "Azure Diagnostic Settings Deleted" to your SIEM and tune for your environment to detect this specific defense evasion technique, focusing on `azure.activitylogs.operation_name:"MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"` and `event.outcome:(Success or success)`.
*   Monitor Azure Activity Logs for `MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE` events to proactively identify and respond to unauthorized changes in logging configurations.
*   Implement strict access controls and policies related to diagnostic settings, ensuring that only trusted and necessary personnel have the ability to modify these settings to prevent unauthorized deletions.
*   Review and update access controls and policies related to diagnostic settings to prevent unauthorized deletions, ensuring that only trusted and necessary personnel have the ability to modify these settings.

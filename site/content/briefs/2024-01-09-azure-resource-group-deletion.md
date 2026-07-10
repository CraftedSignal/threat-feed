---
title: Azure Resource Group Deletion Detected
slug: 2024-01-09-azure-resource-group-deletion
description: This rule detects the deletion of a resource group in Azure. Deleting a resource group permanently removes all resources within it, which adversaries may use to evade defenses or destroy data.
date: "2024-01-09T14:27:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - resource-group
  - deletion
  - impact
vendors:
  - Microsoft
products:
  - Microsoft Azure
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1529
    technique_name: System Shutdown/Reboot
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal
rules:
  - title: Azure Resource Group Deleted
    description: Detects the deletion of a resource group in Azure Activity Logs
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Azure User with High Privileges deleted Resource Group
    description: Detects a deletion of a resource group by a user account with high privileges
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

The deletion of an Azure Resource Group is a significant event that can indicate malicious activity. A resource group acts as a container for Azure resources, and its deletion removes all contained resources permanently and irreversibly. An adversary may leverage resource group deletion to disrupt services, destroy data, or evade detection by eliminating evidence of their presence. This activity is often performed after other malicious actions, such as data exfiltration or system compromise, to cover tracks and maximize impact. This detection identifies the "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE" operation within Azure activity logs, focusing on successful deletion attempts. The scope of targeting is broad, as any Azure environment is susceptible.

## Attack Chain

1.  Initial Access: The attacker gains unauthorized access to an Azure account or service principal with sufficient privileges.
2.  Privilege Escalation (if needed): The attacker escalates their privileges within the Azure environment to gain the ability to delete resource groups.
3.  Discovery: The attacker identifies resource groups containing valuable data or critical services using Azure Resource Manager or similar tools.
4.  Defense Evasion: The attacker disables or modifies security tools and logging configurations to prevent detection of their activity (T1562.001).
5.  Data Destruction: The attacker initiates the deletion of the identified resource groups via the Azure portal, CLI, or API, using the `MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE` operation.
6.  Inhibit System Recovery: The attacker deletes backups or snapshots associated with the resource groups to hinder recovery efforts (T1490).
7.  Service Stop: The deletion of the resource group terminates any services running within it, leading to service disruption (T1489).
8.  Impact: The targeted services and data are permanently deleted, causing significant operational disruption and potential data loss.

## Impact

The deletion of an Azure resource group can have severe consequences. It leads to the immediate and irreversible loss of all resources within the group, potentially impacting critical services, applications, and data. The number of affected users and the extent of the damage depend on the contents of the deleted resource group. Successful attacks can result in business interruption, data loss, reputational damage, and financial losses. The sectors most vulnerable are those heavily reliant on Azure services, including finance, healthcare, and technology.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect Azure resource group deletion events using `data_stream.dataset:azure.activitylogs` and `azure.activitylogs.operation_name:"MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"`.
*   Review Azure activity logs for `MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE` events, focusing on the user identity associated with the deletion.
*   Implement strict access control policies to limit the ability to delete resource groups to only authorized personnel.
*   Monitor for modifications to security tools or logging configurations as described in technique T1562.001 before resource group deletion events.
*   Create and regularly test backup and recovery procedures for Azure resources to mitigate the impact of accidental or malicious deletions (T1490).
*   Investigate any unexpected or unauthorized resource group deletions immediately and thoroughly.

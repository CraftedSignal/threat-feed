---
title: Azure Event Hub Deletion for Defense Evasion
slug: 2024-01-09-azure-eventhub-deletion
description: Detection of Azure Event Hub deletion, indicative of defense evasion by adversaries seeking to disrupt data flow and evade detection by erasing log evidence.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - azure
  - defense-evasion
vendors:
  - Microsoft
products:
  - Azure Event Hub
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-about
  - https://azure.microsoft.com/en-in/services/event-hubs/
  - https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-features
rules:
  - title: Azure Event Hub Deleted
    description: Detects the deletion of an Event Hub in Azure Activity Logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Azure Event Hub Namespace Deletion
    description: Detects the deletion of an Event Hub Namespace in Azure Activity Logs which may contain multiple event hubs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

This alert identifies the deletion of an Azure Event Hub, a critical event processing service for ingesting and processing large volumes of data in real-time. Attackers may target Event Hubs for deletion in an attempt to evade detection by erasing evidence of their activities or to disrupt data flow. The rule focuses on identifying successful deletion operations within Azure activity logs, specifically looking for the "MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE" event. The monitoring of Event Hub deletion is crucial because successful deletion can lead to data loss, service disruption, and an increased dwell time for attackers due to the removal of forensic data.

## Attack Chain

1. An attacker gains unauthorized access to an Azure account, potentially through compromised credentials or exploiting a vulnerability.
2. The attacker escalates privileges within the Azure environment to obtain the necessary permissions to manage Event Hubs.
3. The attacker identifies Event Hubs within the target environment that contain valuable log data.
4. The attacker initiates a deletion request for a specific Event Hub using the Azure portal, CLI, or API.
5. Azure processes the deletion request, logging the event with the operation name "MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE".
6. The Event Hub is successfully deleted, resulting in the removal of associated log data and potentially disrupting data streams.
7. The attacker attempts to cover their tracks by deleting or modifying other related logs within the Azure environment.

## Impact

Successful deletion of Azure Event Hubs can lead to a significant loss of log data, hindering incident response and forensic investigations. This can allow attackers to operate undetected for longer periods, increasing the potential for further damage. Service disruption can also occur if the deleted Event Hub was critical for real-time data processing. While the exact number of victims is unknown, organizations relying on Azure Event Hubs for security monitoring and data analytics are at risk.

## Recommendation

*   Deploy the Sigma rule to detect Event Hub deletions (see `rules` section) in your SIEM, and tune for your environment.
*   Review Azure RBAC permissions to ensure only authorized personnel have Event Hub deletion rights.
*   Enable multi-factor authentication (MFA) for all Azure accounts to prevent unauthorized access (reference: [https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-about](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-about)).
*   Implement additional monitoring and alerting for Azure Event Hub operations to detect and respond to unauthorized activities promptly.

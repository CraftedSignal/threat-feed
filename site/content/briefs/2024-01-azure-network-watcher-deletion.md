---
title: Azure Network Watcher Deletion for Defense Evasion
slug: 2024-01-azure-network-watcher-deletion
description: An adversary may delete an Azure Network Watcher to impair defenses by disabling network monitoring and logging capabilities, as detected by monitoring Azure activity logs for Network Watcher deletion events.
date: "2024-01-03T15:00:00Z"
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
  - Azure Network Watcher
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
  - https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
  - https://attack.mitre.org/techniques/T1562/008/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Azure Network Watcher Deleted
    description: Detects the deletion of a Network Watcher in Azure Activity Logs, indicating a potential defense evasion attempt.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
      - T1562.008
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Azure Network Watcher Deletion by Unusual Identity
    description: Detects Network Watcher deletion events performed by service principals or user accounts that are not typically associated with network infrastructure management.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
      - T1562.008
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

Azure Network Watcher is a critical tool for monitoring, diagnosing, and logging network activity within Azure virtual networks. This tool provides crucial insights for maintaining network security and performance. An attacker with sufficient privileges can delete a Network Watcher instance to evade defenses by disabling network monitoring, traffic analysis, and logging capabilities. This event can be triggered through the Azure portal, CLI, or API. The deletion event is recorded in Azure Activity Logs, providing a valuable opportunity for detection. Detecting the unauthorized deletion of Network Watchers is crucial for maintaining visibility into the network environment and responding to potential security incidents.

## Attack Chain

1. The attacker gains initial access to an Azure account with sufficient privileges to manage Network Watcher resources, potentially through compromised credentials or exploiting a misconfigured service principal.
2. The attacker authenticates to the Azure Resource Manager API or uses the Azure portal with the compromised account.
3. The attacker identifies the target Network Watcher instance within the Azure subscription.
4. The attacker issues a DELETE request to the Azure Resource Manager API targeting the Network Watcher resource, specifically using the "MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE" operation.
5. Azure processes the deletion request, removing the Network Watcher configuration and stopping the associated monitoring and logging activities.
6. The deletion event is recorded in the Azure Activity Logs with an "event.outcome" of "Success" or "success".
7. Without the Network Watcher, the attacker can perform malicious activities within the virtual network with reduced chances of detection.
8. The attacker achieves their objective, such as data exfiltration, lateral movement, or deploying malicious resources, while avoiding network-based monitoring and alerting.

## Impact

The deletion of a Network Watcher can significantly impair an organization's ability to detect and respond to network-based threats within their Azure environment. Successful deletion results in the loss of network traffic analysis, packet capture, and flow logging capabilities provided by Network Watcher. The scope of impact depends on the number of virtual networks and resources monitored by the deleted Network Watcher. This can lead to delayed incident response, increased dwell time for attackers, and greater potential for data breaches or other malicious activities.

## Recommendation

*   Deploy the Sigma rule `Azure Network Watcher Deleted` to your SIEM and tune for your environment, using Azure activity logs to detect unauthorized deletions of Network Watchers.
*   Review Azure activity logs regularly for `MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE` events to identify potential defense evasion attempts.
*   Implement stricter access controls and auditing for Azure resources, ensuring only authorized personnel have the ability to delete critical monitoring tools as described in the overview section.
*   Investigate any identified deletions by examining the associated user identity in the activity logs to confirm authorization, as described in the triage section.
*   Restore deleted Network Watchers by redeploying them in the affected regions to resume monitoring and logging capabilities, as mentioned in the response section.

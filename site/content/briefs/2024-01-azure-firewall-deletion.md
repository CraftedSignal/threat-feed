---
title: Azure VNet Firewall Policy Deletion for Defense Evasion
slug: 2024-01-azure-firewall-deletion
description: An adversary may delete a firewall policy in Azure in an attempt to evade defenses, which can be detected by monitoring Azure activity logs for successful deletion operations of firewall policies.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - azure
  - cloud
  - defense-evasion
vendors:
  - Microsoft
products:
  - Azure Firewall
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.microsoft.com/en-us/azure/firewall-manager/policy-overview
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/007/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Azure VNet Firewall Policy Deleted
    description: Detects the deletion of a firewall policy in Azure.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Azure VNet Firewall Policy Delete Attempt
    description: Detects attempts to delete a firewall policy in Azure, regardless of success.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

Attackers may target Azure Firewall policies to disable security measures, facilitating unauthorized access or data exfiltration. This can be achieved by deleting existing firewall policies, effectively removing the network security rules that protect Azure resources. Monitoring for these deletions allows defenders to identify potential defense evasion attempts. This activity is logged within Azure Activity Logs and can be detected by monitoring for specific operation names related to firewall policy deletion. The scope of this activity includes Azure environments utilizing VNet firewalls and relies on the attacker having sufficient privileges to delete these policies. Successful exploitation of this activity may lead to further compromises in the cloud environment.

## Attack Chain

1.  The attacker gains initial access to an Azure account through compromised credentials or a hijacked session.
2.  The attacker enumerates existing Azure Firewall policies to identify potential targets for deletion.
3.  The attacker attempts to delete a specific Azure Firewall policy using the Azure portal, CLI, or API.
4.  Azure logs the firewall policy deletion attempt in the Activity Log with the operation name `MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE`.
5.  If the attacker has sufficient privileges, the firewall policy is successfully deleted, and the `event.outcome` is recorded as "Success".
6.  With the firewall policy deleted, network traffic that was previously blocked is now allowed, potentially exposing internal resources.
7.  The attacker leverages the now-open network channels to move laterally within the Azure environment.
8.  The attacker achieves their objective, such as data exfiltration or deployment of malicious resources, due to the absence of firewall restrictions.

## Impact

Successful deletion of Azure Firewall policies can lead to significant security breaches. With network security rules removed, attackers gain the ability to bypass previous restrictions. The number of victims is dependent on the scope and scale of the Azure environment and the resources protected by the deleted firewall policies. Targeted sectors could include any organization using Azure VNets for network security. Consequences include unauthorized access to sensitive data, lateral movement within the cloud environment, and potential deployment of malicious resources.

## Recommendation

*   Deploy the Sigma rule "Azure VNet Firewall Policy Deleted" to your SIEM and tune for your environment to detect unauthorized firewall policy deletions via Azure Activity Logs.
*   Review Azure activity logs for events with `azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE"` to identify potential unauthorized deletions.
*   Implement multi-factor authentication (MFA) for all users with permissions to modify or delete firewall policies to reduce the risk of compromised credentials.
*   Configure alerts for any future attempts to delete or modify critical security policies, ensuring rapid detection and response to potential threats in Azure.
*   Restore the deleted firewall policy from backups or recreate it using predefined templates to ensure that network security rules are reinstated promptly.

---
title: Azure Firewall Modification or Deletion Detected
slug: 2024-01-azure-firewall-modified-or-deleted
description: An Azure firewall was created, modified, or deleted, potentially indicating malicious activity aimed at impairing network defenses.
date: "2024-01-03T18:30:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - firewall
  - defense-evasion
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_firewall_modified_or_deleted.yml
rules:
  - title: Azure Firewall Modified or Deleted
    description: Detects when an Azure Firewall is created, modified, or deleted.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - impact
    data_sources:
      - azure
      - activitylogs
  - title: Azure Firewall Rule Modified
    description: Detects modifications to Azure Firewall rules which may indicate malicious intent.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1562.004
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

This alert identifies potentially malicious modifications or deletions of Azure firewalls. Azure firewalls are critical components for network security, controlling inbound and outbound traffic based on defined rules. An attacker who gains sufficient privileges within an Azure environment may attempt to disable or modify these firewalls to facilitate lateral movement, data exfiltration, or other malicious activities. This activity is particularly concerning as it represents a direct attempt to weaken the victim's security posture. The activity is detected via Azure Activity Logs. While legitimate administrative actions can trigger this alert, any unexpected or unauthorized changes to firewall configurations should be investigated promptly.

## Attack Chain

1.  Attacker gains initial access to an Azure environment, possibly through compromised credentials or exploiting a vulnerability in an application.
2.  Attacker escalates privileges within the Azure subscription to gain permissions to manage network resources, including firewalls.
3.  Attacker identifies the Azure firewalls in the target environment using Azure Resource Manager APIs or the Azure portal.
4.  Attacker modifies firewall rules to allow unauthorized traffic, such as opening ports for command and control communication or disabling security rules. This is achieved via the `MICROSOFT.NETWORK/AZUREFIREWALLS/WRITE` operation.
5.  Alternatively, the attacker deletes the Azure firewall using the `MICROSOFT.NETWORK/AZUREFIREWALLS/DELETE` operation, effectively removing network protections.
6.  Attacker validates that their changes have been successfully applied by testing network connectivity or by reviewing the firewall configuration.
7.  Attacker performs malicious activities such as lateral movement, data exfiltration, or deploying additional resources without firewall restrictions.

## Impact

Successful modification or deletion of Azure firewalls can have severe consequences. An attacker can bypass network security controls, leading to data breaches, unauthorized access to sensitive resources, and the potential for widespread disruption. This can result in financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unauthorized firewall modifications or deletions in Azure Activity Logs.
*   Investigate any alerts triggered by the Sigma rule, focusing on unfamiliar user identities and user agents.
*   Review Azure RBAC roles and permissions to ensure the principle of least privilege is enforced, limiting the ability of users and service principals to modify or delete firewalls.
*   Monitor Azure Activity Logs for other suspicious activities, such as unusual resource deployments or changes to security settings.

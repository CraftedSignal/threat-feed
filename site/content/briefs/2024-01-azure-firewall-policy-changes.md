---
title: Azure Network Firewall Policy Modification or Deletion
slug: 2024-01-azure-firewall-policy-changes
description: An adversary may modify or delete Azure Network Firewall Policies to impair defenses and potentially impact network security.
date: "2024-01-03T18:12:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - attack.impact
  - attack.defense-impairment
  - attack.t1686.001
vendors:
  - Microsoft
products:
  - Azure Network Firewall
references:
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_network_firewall_policy_modified_or_deleted.yml
rules:
  - title: Azure Network Firewall Policy Modified
    description: Detects modifications to Azure Network Firewall Policies.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - impact
    data_sources:
      - azure
      - activitylogs
  - title: Azure Network Firewall Policy Join Action
    description: Detects join actions on Azure Network Firewall Policies.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - impact
    data_sources:
      - azure
      - activitylogs
  - title: Azure Network Firewall Policy Deletion
    description: Detects deletion of Azure Network Firewall Policies.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - impact
    data_sources:
      - azure
      - activitylogs
rules_count: 3
---

Attackers may target Azure Network Firewall Policies to weaken an organization's security posture. By modifying existing policies, adversaries can introduce rules that allow malicious traffic, disable existing protections, or create backdoors for future access. Deleting firewall policies altogether removes a critical layer of defense, potentially exposing internal resources to external threats. This activity is typically conducted after gaining initial access to the Azure environment through compromised credentials or other means. Monitoring for unauthorized changes to firewall policies is critical for maintaining network security and preventing potential data breaches or service disruptions.

## Attack Chain

1.  The attacker gains initial access to the Azure environment, possibly through compromised credentials or a vulnerability in a deployed application.
2.  The attacker enumerates existing Azure Network Firewall Policies using Azure CLI or PowerShell commands.
3.  The attacker identifies a firewall policy to modify or delete to achieve their objectives.
4.  If modifying, the attacker uses commands such as `Set-AzNetworkFirewallPolicy` or the Azure portal to alter the policy rules, potentially adding permissive rules or disabling existing restrictions.
5.  If deleting, the attacker uses commands such as `Remove-AzNetworkFirewallPolicy` or the Azure portal to remove the firewall policy entirely.
6.  The changes are applied to the Azure Network Firewall, impacting network traffic filtering.
7.  The attacker validates the effectiveness of the modified or deleted policy by testing network connectivity to previously protected resources.
8.  The attacker proceeds to exploit the newly exposed resources for data exfiltration, lateral movement, or other malicious activities.

## Impact

Successful modification or deletion of Azure Network Firewall policies can lead to significant security breaches. Attackers may be able to bypass network segmentation, gain unauthorized access to sensitive data, disrupt critical services, or deploy malicious code within the network. The impact can range from data theft and financial loss to reputational damage and regulatory penalties. The number of affected resources depends on the scope of the compromised firewall policy and the attacker's subsequent actions.

## Recommendation

*   Implement the Sigma rule "Azure Network Firewall Policy Modified or Deleted" to detect unauthorized changes to firewall policies (logsource: azure, service: activitylogs).
*   Review user identities and user agents associated with detected events to determine if the changes were made by authorized personnel or malicious actors, as detailed in the false positives section.
*   Enable multi-factor authentication (MFA) for all Azure accounts to reduce the risk of credential compromise.
*   Enforce the principle of least privilege by granting users only the necessary permissions to manage firewall policies.
*   Implement continuous monitoring and alerting for all Azure resources, including network firewalls, to detect suspicious activity and potential security breaches.

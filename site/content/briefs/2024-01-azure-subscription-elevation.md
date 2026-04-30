---
title: Azure Subscription Permission Elevation via Activity Logs
slug: 2024-01-azure-subscription-elevation
description: An attacker elevates their Azure subscription permissions to manage all subscriptions, potentially leading to unauthorized access and control over the environment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - privilege-escalation
  - persistence
  - initial-access
  - stealth
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftauthorization
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_subscription_permissions_elevation_via_activitylogs.yml
rules:
  - title: Azure Subscription Permission Elevation Via ActivityLogs
    description: Detects when a user has been elevated to manage all Azure Subscriptions. This change should be investigated immediately if it isn't planned.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - azure
      - activitylogs
  - title: Azure Subscription Role Assignment - Potential Privilege Escalation
    description: Detects creation of new role assignments at the subscription level, which can be used for privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

This threat involves the elevation of user permissions within an Azure environment to manage all Azure subscriptions. While legitimate administrators may perform this action, unauthorized elevation of permissions can grant an attacker significant control over the entire Azure environment. This could be an insider threat or a compromised account being used to broaden access. The activity is logged within Azure Activity Logs, providing an opportunity for detection. Defenders should be aware of this potential escalation path and monitor for unexpected or unauthorized permission changes.

## Attack Chain

1.  The attacker gains initial access to an Azure account, potentially through compromised credentials (T1078.004).
2.  The attacker authenticates to the Azure portal or uses Azure CLI/PowerShell with the compromised account.
3.  The attacker attempts to elevate their permissions using the `MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION` operation.
4.  Azure Activity Logs record the attempt to elevate permissions.
5.  If successful, the attacker gains management access to all Azure subscriptions within the tenant.
6.  The attacker can then provision resources, modify configurations, and access data within those subscriptions.
7.  The attacker might establish persistence by creating new user accounts with elevated privileges or modifying existing roles.
8.  The attacker can then exfiltrate sensitive data or disrupt services within the Azure environment.

## Impact

Successful elevation of permissions to manage all Azure subscriptions allows an attacker to control all resources, data, and configurations within the Azure environment. This can lead to data breaches, service disruptions, financial loss, and reputational damage. The scope of impact depends on the sensitivity of the data stored within Azure and the criticality of the services hosted there.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unauthorized `MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION` operations in Azure Activity Logs.
*   Investigate any detected instances of `MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION` immediately, as outlined in the rule description.
*   Implement multi-factor authentication (MFA) for all Azure accounts to reduce the risk of credential compromise.
*   Review and enforce the principle of least privilege for Azure role assignments.
*   Monitor Azure Activity Logs for other suspicious activities, such as unusual resource creation or modification.

---
title: Detection of Azure Subscription Permission Elevation
slug: 2024-01-03-azure-privilege-elevation
description: Detection of a user being assigned the 'User Access Administrator' role, which grants the ability to manage all Azure Subscriptions, potentially leading to privilege escalation and unauthorized access.
date: "2024-01-03T15:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - attack.privilege-escalation
  - attack.persistence
  - attack.initial-access
  - attack.stealth
  - attack.t1078
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts#assignment-and-elevation
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_subscription_permissions_elevation_via_auditlogs.yml
rules:
  - title: Azure Subscription Permission Elevation Via AuditLogs
    description: Detects when a user has been elevated to manage all Azure Subscriptions via the 'Assigns the caller to user access admin' event. This change should be investigated immediately if it isn't planned.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - auditlogs
  - title: Azure Subscription Permission Elevation Via AuditLogs - Alternative Operation Name
    description: Detects when a user has been elevated to manage all Azure Subscriptions using an alternative OperationName value, indicative of similar privilege escalation actions.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

This threat brief focuses on detecting unauthorized elevation of privileges within Azure environments. Specifically, it addresses the assignment of the 'User Access Administrator' role to a user, which allows managing access to all Azure subscriptions. This activity can be indicative of malicious actors attempting to gain control over an Azure environment or an insider threat escalating their privileges without proper authorization. The detection is based on Azure Audit Logs and can help identify potentially compromised accounts or misconfigurations. A successful elevation can lead to unauthorized access, data breaches, and service disruptions. Defenders should closely monitor these events and investigate any unexpected privilege escalations.

## Attack Chain

1. An attacker gains initial access to an Azure account, possibly through compromised credentials or exploiting a vulnerability.
2. The attacker attempts to assign the 'User Access Administrator' role to themselves or another account they control.
3. This assignment generates an 'Administrative' audit log event with the OperationName 'Assigns the caller to user access admin'.
4. The attacker now has the ability to manage user access to all Azure subscriptions within the tenant.
5. The attacker creates new user accounts with elevated privileges within the subscriptions.
6. The attacker leverages the newly created accounts to access sensitive resources and data.
7. The attacker performs reconnaissance activities to identify critical assets and data stores.
8. The attacker exfiltrates sensitive data or deploys malicious workloads within the compromised subscriptions.

## Impact

A successful privilege escalation to the 'User Access Administrator' role can have severe consequences. It grants the attacker complete control over the Azure subscriptions, allowing them to access sensitive data, disrupt services, and potentially compromise the entire cloud environment. The number of affected subscriptions depends on the scope of the compromised account. This attack targets any organization utilizing Azure subscriptions and is particularly impactful for those storing sensitive data or running critical applications in the cloud.

## Recommendation

*   Deploy the provided Sigma rule "Azure Subscription Permission Elevation Via AuditLogs" to your SIEM and tune it for your environment to detect the 'Assigns the caller to user access admin' event in the Azure Audit Logs.
*   Investigate any detected instances of this event to determine if the privilege elevation was authorized and legitimate.
*   Review and enforce the principle of least privilege for all Azure accounts to minimize the impact of potential compromises; reference the Microsoft Entra documentation for guidance.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges, to prevent unauthorized access via compromised credentials.

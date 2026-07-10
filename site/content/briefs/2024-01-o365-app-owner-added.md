---
title: O365 Application Registration Owner Added
slug: 2024-01-o365-app-owner-added
description: A new owner added to an O365 application registration can grant significant control, potentially leading to unauthorized data access, privilege escalation, or malicious behavior.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - NOBELIUM Group
tags:
  - azuread
  - o365
  - persistence
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Office 365
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/overview-assign-app-owners
rules:
  - title: O365 Application Registration Owner Added
    description: Detects when a new owner is added to an application registration in O365, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - o365
      - o365
  - title: Suspicious O365 Application Owner Addition by Uncommon User
    description: Detects O365 application owner additions performed by users who rarely or never perform this action, potentially indicating compromised accounts or insider threats.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1098
    data_sources:
      - o365
      - o365
  - title: O365 Application Registration Owner Added - PowerShell
    description: Detects adding a new owner to an application registration via PowerShell, which could indicate malicious automation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - persistence
    techniques:
      - T1098
    data_sources:
      - o365
      - o365
rules_count: 3
---

The addition of a new owner to an application registration in Azure AD and Office 365 tenants is a notable security event. Attackers may target application registrations to gain persistence or elevate privileges within an organization. The Splunk ES content published on 2026-04-17 detects this activity by monitoring O365 audit logs for events related to changes in owner assignments within the AzureActiveDirectory workload. This technique can be used by threat actors like NOBELIUM to establish persistence mechanisms within compromised environments. Successfully adding a malicious owner to an application registration can allow the attacker to modify application settings, permissions, and behavior, leading to unauthorized data access, privilege escalation, or the introduction of malicious behavior within the application's operations.

## Attack Chain

1. The attacker gains initial access to a compromised user account, potentially through phishing or credential stuffing.
2. The attacker logs into the Azure portal using the compromised account.
3. The attacker navigates to the Azure Active Directory section.
4. The attacker identifies a target application registration to compromise.
5. The attacker uses the compromised account to add a new owner to the application registration via the Azure portal or PowerShell cmdlets.
6. The attacker configures the compromised application registration with malicious settings or permissions.
7. The attacker uses the compromised application registration to gain unauthorized access to data or resources.
8. The attacker leverages the compromised application registration for persistence within the environment.

## Impact

Successful exploitation of this technique can allow attackers to establish persistence within the compromised environment, escalate privileges, and gain unauthorized access to sensitive data. This can lead to data breaches, financial loss, and reputational damage. The number of affected users and the scope of the damage will vary depending on the permissions and configurations of the compromised application registration.

## Recommendation

*   Deploy the Sigma rule "O365 Application Registration Owner Added" to your SIEM and tune for your environment.
*   Enable O365 management activity logging to ensure the necessary events are captured (data_source: "O365 Add owner to application.").
*   Review and monitor application registration owner assignments for any suspicious or unauthorized changes (references: "https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/overview-assign-app-owners").
*   Investigate any alerts triggered by the Sigma rule, focusing on the user and object involved (rule: "O365 Application Registration Owner Added").

---
title: Azure AD User Added to Administrator Role
slug: 2024-01-azuread-admin-role-add
description: An adversary adds a user to an Azure Active Directory administrative role to gain initial access, persist in the environment, escalate privileges, and potentially operate stealthily.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.initial-access
  - attack.persistence
  - attack.privilege-escalation
  - attack.stealth
  - attack.t1098.003
  - attack.t1078
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_ad_user_added_to_admin_role.yml
rules:
  - title: Detect User Added to Azure AD Admin Role
    description: Detects when a user is added to an Azure AD administrative role using Azure Activity Logs.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
      - T1098.003
    data_sources:
      - azure
      - activitylogs
  - title: Detect Azure AD Role Assignment via Azure CLI
    description: Detects Azure AD role assignment activity performed through the Azure CLI.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
      - T1098.003
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

Attackers may attempt to add new members to administrative roles in Azure Active Directory to establish persistence and elevate privileges. This allows them to perform actions as a highly privileged user, potentially bypassing security controls and accessing sensitive resources. The activity is logged within Azure Activity Logs, specifically when the 'Add member to role' operation is executed within the 'AzureActiveDirectory' workload, targeting roles with names ending in 'Admins' or 'Administrator'. Monitoring these events can help detect unauthorized privilege escalation and potential malicious activity within the Azure environment. This activity could be the result of compromised credentials or an insider threat.

## Attack Chain

1.  Compromise an existing user account with sufficient permissions to modify Azure AD roles.
2.  Authenticate to the Azure portal or utilize Azure CLI with the compromised account.
3.  Identify a target Azure AD administrative role (e.g., Global Administrator, Security Administrator).
4.  Execute the 'Add member to role' operation, adding the attacker-controlled user to the target role. This can be performed via the Azure portal, PowerShell, or Azure CLI.
5.  The Azure Activity Logs record the 'Add member to role.' event, with the 'Workload' as 'AzureActiveDirectory'.
6.  The `ModifiedProperties{}.NewValue` field reflects the addition of the user to the admin role, containing strings like "Admins" or "Administrator."
7.  The attacker authenticates as the newly added user, inheriting the privileges of the administrative role.
8.  The attacker leverages the elevated privileges to access sensitive data, modify configurations, or deploy malicious applications.

## Impact

Successful addition of a user to an Azure AD administrative role grants the attacker extensive control over the Azure environment. This can lead to data breaches, service disruptions, and the deployment of malicious applications.  Compromised administrator accounts can be used to disable security features, modify audit logs, and create backdoors for persistent access. Detection is critical to limit the scope and duration of the attack.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect instances of users being added to Azure AD administrative roles (logsource: azure, service: activitylogs).
*   Investigate any detected instances of the "Add member to role." operation in Azure AD Activity Logs where the ModifiedProperties{}.NewValue ends with 'Admins' or 'Administrator' to validate legitimate administrative changes.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges, to mitigate the risk of compromised credentials.
*   Regularly review Azure AD role assignments to identify and remove unnecessary privileges.
*   Monitor for unusual activity from newly added members of administrative roles after the 'Add member to role' event.

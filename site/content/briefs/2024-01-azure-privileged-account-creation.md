---
title: Detection of Privileged Account Creation in Azure
slug: 2024-01-azure-privileged-account-creation
description: Detects the creation of new privileged accounts in Azure environments, potentially indicating initial access, persistence, privilege escalation, or stealth activities by malicious actors.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - privileged-account
  - initial-access
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts#changes-to-privileged-accounts
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml
rules:
  - title: Azure AD - Privileged Account Creation
    description: Detects when a new admin is created in Azure AD Audit Logs.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD - User Assigned to Privileged Role
    description: Detects when a user is assigned to a highly privileged role in Azure AD Audit Logs.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

This threat brief focuses on the detection of new privileged account creation within Azure environments. Attackers often create new admin accounts to establish persistence, escalate privileges, or move laterally within a compromised environment. Monitoring for such activity is crucial, especially given that compromised accounts are a common entry point for various attacks. This activity, if malicious, can lead to significant data breaches, service disruptions, and reputational damage. This detection focuses on identifying "Add user" and "Add member to role" events within Azure audit logs.

## Attack Chain

1. An attacker gains initial access to an Azure environment, possibly through compromised credentials (T1078.004).
2. The attacker leverages their access to enumerate existing accounts and roles within the Azure Active Directory.
3. The attacker attempts to create a new user account with elevated privileges, such as Global Administrator or other custom administrative roles.
4. The attacker assigns the newly created user account to one or more privileged roles, granting it administrative access to the Azure environment. This action is logged as "Add member to role".
5. The attacker uses the newly created privileged account to perform reconnaissance, identify sensitive data, or deploy malicious applications.
6. The attacker establishes persistence by maintaining access through the newly created account, even if the initial entry point is detected and remediated.
7. The attacker escalates privileges to gain control over critical resources and services within the Azure environment.
8. The attacker uses the privileged account to exfiltrate sensitive data, deploy ransomware, or disrupt critical business operations.

## Impact

Successful creation of a privileged account can provide an attacker with persistent access and the ability to escalate privileges, leading to widespread damage. The attacker can gain control over critical resources, exfiltrate sensitive data, deploy ransomware, or disrupt business operations. This can lead to significant financial losses, reputational damage, and legal liabilities. While the scope and number of victims are unknown, all organizations using Azure Active Directory are potentially at risk.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect privileged account creation events within Azure Audit Logs.
*   Investigate any detected instances of privileged account creation to determine whether the activity is legitimate.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with privileged roles, to mitigate the risk of credential compromise (T1110).
*   Regularly review and audit user account privileges to identify and remove unnecessary or excessive permissions.
*   Monitor Azure Audit Logs for suspicious activities, such as unusual sign-in attempts, changes to security settings, and modifications to privileged roles.
*   Implement alerting for changes to privileged roles and groups within Azure AD.

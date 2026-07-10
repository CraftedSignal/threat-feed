---
title: Azure AD PowerShell Authentication Abuse
slug: 2024-01-03-azuread-powershell-auth
description: Adversaries may compromise accounts and leverage successful PowerShell authentication in Azure AD to enumerate cloud resources, escalate privileges, and further exploit the Azure environment.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - powershell
  - authentication
  - cloud
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Azure PowerShell
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://attack.mitre.org/techniques/T1078/004/
  - https://docs.microsoft.com/en-us/powershell/module/azuread/connect-azuread?view=azureadps-2.0
  - https://securitycafe.ro/2022/04/29/pentesting-azure-recon-techniques/
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md
rules:
  - title: Detect Azure AD Successful PowerShell Authentication
    description: Detects successful authentication to Azure AD using the Microsoft Azure PowerShell application.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078.004
    data_sources:
      - webserver
      - linux
  - title: Detect Azure AD PowerShell Authentication - Alternate
    description: Detects successful authentication to Azure AD using the Microsoft Azure PowerShell application by checking user agent.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief focuses on the abuse of successful PowerShell authentication within Azure Active Directory (Azure AD) environments. Attackers who have compromised user accounts or obtained valid credentials may leverage the "Microsoft Azure PowerShell" application to connect to Azure AD. This activity is notable because it's atypical for regular, non-administrative users to authenticate using PowerShell cmdlets. The observed behavior can be indicative of reconnaissance, lateral movement, or privilege escalation attempts. The techniques described here are relevant to defenders responsible for monitoring cloud environments and detecting anomalous authentication patterns. The information is based on observed patterns of abuse and recommended best practices for securing Azure AD.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access through compromised credentials obtained via phishing, password spraying (T1586.003), or other credential access techniques.
2.  **Successful Authentication:** The attacker successfully authenticates to Azure AD using the compromised credentials.
3.  **PowerShell Authentication:** The attacker authenticates to Azure AD using the Microsoft Azure PowerShell application.
4.  **Account Enumeration:** The attacker uses PowerShell cmdlets (e.g., `Get-AzureADUser`) to enumerate user accounts within the Azure AD tenant.
5.  **Group Enumeration:** The attacker uses PowerShell cmdlets (e.g., `Get-AzureADGroup`) to identify Azure AD groups and their members.
6.  **Role Discovery:** The attacker uses PowerShell cmdlets (e.g., `Get-AzureADRoleAssignment`) to discover assigned roles and permissions.
7.  **Resource Discovery:** The attacker identifies Azure resources (VMs, storage accounts, databases) accessible to the compromised account or through discovered roles.
8.  **Lateral Movement/Privilege Escalation:** Based on discovered resources and roles, the attacker attempts lateral movement to other systems or privilege escalation to gain higher-level access.

## Impact

A successful attack exploiting PowerShell authentication in Azure AD can result in significant damage. Attackers can gain unauthorized access to sensitive data, disrupt cloud services, and compromise critical infrastructure. The impact can range from data breaches and financial losses to reputational damage and regulatory fines. The compromised account's level of access will determine the scope of the damage, but even limited access can provide a foothold for further exploitation.

## Recommendation

*   Deploy the provided Sigma rule to detect successful Azure AD PowerShell authentications and investigate any anomalous activity (rules).
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges, to mitigate the risk of credential compromise (T1078.004).
*   Enforce the principle of least privilege to limit the permissions of user accounts and reduce the potential impact of a successful attack (T1078.004).
*   Review and restrict user access to the "Microsoft Azure PowerShell" application to only authorized users (rules).
*   Monitor Azure AD sign-in logs for unusual authentication patterns, such as logins from unfamiliar locations or devices (data_source).
*   Implement alerting based on the included analytic story "Azure Active Directory Account Takeover" (tags).

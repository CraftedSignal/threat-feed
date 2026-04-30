---
title: Azure Domain Federation Settings Modified
slug: 2024-01-azure-federation-modification
description: An attacker may modify Azure domain federation settings to establish persistence, escalate privileges, or gain unauthorized access to resources.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - federation
  - privilege-escalation
  - persistence
  - initial-access
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-monitor-federation-changes
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_federation_modified.yml
rules:
  - title: Azure Domain Federation Settings Modified
    description: Identifies when a user or application modifies the federation settings on the domain.
    platform: sigma
    severity: medium
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
  - title: Azure AD Federation Settings Changes via PowerShell
    description: Detects changes to Azure AD federation settings via PowerShell commands.
    platform: sigma
    severity: medium
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

Attackers can modify federation settings on Azure domains to gain unauthorized access and establish persistence. This involves manipulating the trust relationships between the Azure Active Directory and external identity providers. By altering these settings, an attacker can potentially bypass normal authentication mechanisms, assume identities, and maintain a foothold within the environment. This activity is typically carried out by users or applications with administrative privileges, making it crucial to monitor and validate any changes made to the federation settings. Detecting such modifications can be challenging due to the legitimate use of these settings by system administrators. This activity falls under tactics such as privilege escalation, persistence, initial access, and stealth.

## Attack Chain

1.  The attacker gains initial access to an account with sufficient privileges to manage Azure Active Directory settings, such as a Global Administrator or Privileged Role Administrator.
2.  The attacker authenticates to the Azure portal or uses PowerShell/CLI to interact with Azure resources.
3.  The attacker enumerates existing domain federation settings to understand the current configuration and identify potential targets for modification.
4.  The attacker modifies the federation settings on the domain using commands like `Set-MsolDomainFederationSettings` or through the Azure portal interface. This may involve altering the trusted certificate, changing the issuer URI, or modifying other federation parameters.
5.  The attacker tests the modified federation settings to ensure they can successfully authenticate using the altered configuration.
6.  The attacker leverages the modified federation settings to impersonate users or applications, gaining unauthorized access to protected resources and services.
7.  The attacker establishes persistence by creating backdoors or alternate authentication methods using the modified federation settings.

## Impact

Successful modification of Azure domain federation settings can lead to significant consequences, including unauthorized access to sensitive data, privilege escalation, and long-term persistence within the Azure environment. Attackers could potentially compromise entire domains, impacting all users and applications relying on the affected Azure Active Directory. This can result in data breaches, service disruptions, and reputational damage.

## Recommendation

*   Implement the Sigma rule "Azure Domain Federation Settings Modified" to detect suspicious modifications to federation settings in Azure audit logs.
*   Regularly review and validate changes to Azure domain federation settings, focusing on unfamiliar users and unexpected modifications.
*   Monitor Azure audit logs for the "Set federation settings on domain" event to identify potential tampering.
*   Enforce multi-factor authentication (MFA) for all accounts with administrative privileges to reduce the risk of unauthorized access.
*   Implement the principle of least privilege, granting users only the necessary permissions to perform their tasks.

---
title: Azure AD Temporary Access Pass Added to Account
slug: 2024-01-azure-tap-added
description: Detection of a temporary access pass (TAP) being added to an Azure AD account, which could indicate potential privilege escalation, initial access, persistence, or stealth activity.
date: "2024-01-03T15:30:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azuread
  - temporary-access-pass
  - privilege-escalation
  - initial-access
  - persistence
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts#changes-to-privileged-accounts
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_tap_added.yml
rules:
  - title: Azure AD TAP Added to Account
    description: Detects when a temporary access pass (TAP) is added to an account in Azure AD audit logs.
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
      - auditlogs
  - title: Azure AD TAP Addition by Non-Admin
    description: Detects when a temporary access pass (TAP) is added to an account by a user who is not typically an administrator.
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
rules_count: 2
---

This alert identifies when a temporary access pass (TAP) is added to an Azure Active Directory (Azure AD) account. TAPs are intended for temporary use, allowing users to access resources or perform actions without needing a password. While legitimate use cases exist, adversaries can leverage TAPs to gain unauthorized access, escalate privileges, establish persistence, or move laterally within an Azure environment. This activity warrants investigation, especially if the TAP is added to a privileged account. The source material does not indicate a specific campaign or threat actor, but the technique aligns with common cloud-based attack vectors.

## Attack Chain

1.  **Initial Compromise (Optional):** An attacker gains initial access to an Azure AD account through compromised credentials or other means.
2.  **Privilege Escalation (Optional):** The attacker escalates privileges to an account with sufficient permissions to manage TAPs.
3.  **TAP Generation:** The attacker, using an account with appropriate permissions, generates a temporary access pass (TAP) for a target account.
4.  **TAP Activation:** The attacker uses the TAP to authenticate to the target account.
5.  **Resource Access:** Once authenticated, the attacker gains access to resources and applications associated with the target account.
6.  **Lateral Movement (Optional):** The attacker uses the compromised account to access other resources or accounts within the environment.
7.  **Persistence (Optional):** The attacker establishes persistence by creating new credentials or modifying existing ones, if permissions allow.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, systems, and applications within the Azure environment. Compromised privileged accounts can grant attackers control over critical infrastructure, leading to data breaches, service disruptions, and reputational damage. The impact depends on the permissions associated with the compromised account and the resources accessible through the TAP.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect TAP additions in Azure AD audit logs (see rules).
*   Investigate any instances where TAPs are added to privileged accounts in Azure AD, as highlighted in the rule description and references.
*   Review Azure AD audit logs for suspicious activity surrounding the TAP generation event, including the source IP address and user agent (see rules).
*   Monitor for anomalous sign-in activity using TAPs, specifically focusing on unusual locations or devices.

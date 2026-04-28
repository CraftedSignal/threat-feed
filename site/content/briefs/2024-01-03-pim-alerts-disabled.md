---
title: Privileged Identity Management (PIM) Alerting Disabled
slug: 2024-01-03-pim-alerts-disabled
description: An adversary disables Privileged Identity Management (PIM) alerts in Azure to evade detection and maintain persistent access with escalated privileges.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - pim
  - alerts
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_pim_alerts_disabled.yml
rules:
  - title: PIM Alert Setting Changes To Disabled
    description: Detects when PIM alerts are set to disabled.
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
  - title: PIM Alert Setting Changes - Possible API Access
    description: Detects when PIM alerts are set to disabled, using API-related audit logs
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

Attackers may disable PIM alerts within Azure environments to weaken security monitoring and maintain a low profile while escalating privileges. This involves modifying alert settings within the Azure Privileged Identity Management service to prevent notifications of suspicious or unauthorized activity. This technique enables attackers to operate with reduced scrutiny, making it easier to establish persistence and move laterally within the compromised environment. Successful disabling of PIM alerts allows malicious actors to abuse privileged roles without triggering immediate alarms. This allows for potentially long-term access and control over critical resources.

## Attack Chain

1.  Initial Access: The attacker gains initial access to an Azure account, potentially through compromised credentials or exploiting a vulnerability.
2.  Privilege Escalation: The attacker attempts to escalate privileges within the Azure Active Directory, potentially by exploiting misconfigured roles or vulnerabilities.
3.  PIM Access: The attacker accesses the Azure Privileged Identity Management (PIM) service.
4.  Alert Configuration Discovery: The attacker enumerates existing PIM alert configurations to identify the alerts to be disabled.
5.  Alert Modification: The attacker modifies the alert settings, setting them to disabled. This is often done through the Azure portal or via API calls.
6.  Persistence: With alerts disabled, the attacker can maintain persistence by assigning themselves privileged roles without generating notifications.
7.  Lateral Movement: The attacker leverages the newly acquired privileged roles to move laterally within the Azure environment, accessing sensitive resources and data.

## Impact

Disabling PIM alerts significantly reduces an organization's visibility into privileged access activities. This can lead to delayed detection of malicious activities, enabling attackers to maintain a persistent presence, escalate privileges, and exfiltrate sensitive data without triggering alarms. The impact includes potential data breaches, financial losses, and reputational damage. The lack of alerts hinders incident response efforts and prolongs the duration of the attack, compounding the damage.

## Recommendation

*   Deploy the provided Sigma rule to detect instances where PIM alerts are disabled by monitoring `auditlogs` for `properties.message: Disable PIM Alert`.
*   Regularly review PIM alert configurations to ensure critical alerts are enabled and properly configured.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges, to mitigate initial access (T1078).
*   Enforce the principle of least privilege to limit the scope of potential damage from compromised accounts.
*   Monitor Azure audit logs for unusual activity related to PIM configuration changes.

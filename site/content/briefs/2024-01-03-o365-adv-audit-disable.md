---
title: O365 Advanced Audit Disabled
slug: 2024-01-03-o365-adv-audit-disable
description: The O365 Advanced Audit feature provides critical logging and insights into user and administrator activities, and this analytic detects instances where it is disabled for a specific user, potentially blinding security teams to malicious actions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - o365
  - audit
  - defense-evasion
  - persistence
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
  - https://www.mandiant.com/sites/default/files/2022-08/remediation-hardening-strategies-for-m365-defend-against-apt29-white-paper.pdf
  - https://www.csoonline.com/article/570381/microsoft-365-advanced-audit-what-you-need-to-know.html
rules:
  - title: O365 Advanced Audit Disabled via Change User License
    description: Detects instances where the O365 advanced audit is disabled for a specific user by monitoring O365 audit logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - o365
      - o365
  - title: O365 Advanced Audit Disabled - AzureAD Module
    description: Detects PowerShell activity disabling O365 Advanced Audit
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The O365 Advanced Audit feature in Microsoft 365 provides detailed logging of user and administrator activities. Disabling this feature can significantly reduce visibility into potentially malicious actions within an organization's Microsoft 365 environment. Attackers may disable advanced auditing to evade detection while performing malicious activities such as unauthorized data access, data exfiltration, or account compromise. This detection focuses on identifying instances where the "M365_ADVANCED_AUDITING" plan is disabled for a user, based on Office 365 management activity events. This activity is tracked via AzureActiveDirectory workloads. Identifying this activity allows defenders to quickly identify gaps in logging coverage.

## Attack Chain

1. An attacker gains initial access to a privileged user account within the O365 tenant. This could be achieved through phishing, credential stuffing, or other methods.
2. The attacker authenticates to the O365 portal with the compromised account.
3. The attacker navigates to the Azure Active Directory admin center.
4. The attacker locates the target user account for which they want to disable advanced auditing.
5. The attacker modifies the user's license, specifically removing the "M365_ADVANCED_AUDITING" plan. This action generates an "Change user license" event in the O365 management activity logs.
6. The "extendedAuditEventCategory" property in the log indicates an audit license change. The "DisabledPlans" property is checked for the presence of "M365_ADVANCED_AUDITING".
7. With advanced auditing disabled, the attacker performs malicious activities within the user's account, such as accessing sensitive data or exfiltrating information, with a reduced risk of detection.
8. The attacker maintains persistence within the compromised account, leveraging the disabled audit logging to avoid detection over an extended period.

## Impact

Disabling O365 advanced auditing can lead to a significant reduction in visibility into user and administrator activities. Attackers can exploit this lack of visibility to perform unauthorized actions such as data exfiltration, account compromise, and lateral movement within the O365 environment. If successful, this can lead to data breaches, financial loss, and reputational damage. Without advanced auditing enabled, investigations into security incidents become significantly more challenging and time-consuming.

## Recommendation

*   Deploy the Sigma rule provided below to your SIEM to detect instances of O365 advanced audit being disabled (Sigma rule).
*   Investigate any detected instances of disabled advanced auditing to determine if the change was authorized and legitimate.
*   Implement multi-factor authentication (MFA) for all user accounts, especially privileged accounts, to reduce the risk of account compromise (TTP:TA0001).
*   Review and harden O365 security configurations based on Microsoft's best practices and industry standards (Reference: https://www.mandiant.com/sites/default/files/2022-08/remediation-hardening-strategies-for-m365-defend-against-apt29-white-paper.pdf).
*   Monitor O365 management activity logs for other suspicious activities, such as changes to security policies or the creation of new accounts with elevated privileges.
*   Ensure that all administrators are aware of the importance of advanced auditing and the potential risks associated with disabling it.

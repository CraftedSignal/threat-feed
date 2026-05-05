---
title: O365 Advanced Audit Disabled
slug: 2024-01-o365-advanced-audit-disabled
description: Detection of O365 advanced audit being disabled for a specific user, potentially allowing attackers to operate with reduced risk of detection, leading to unauthorized data access, data exfiltration, or account compromise.
date: "2024-01-03T18:15:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - o365
  - audit
  - defense-evasion
  - persistence
vendors:
  - Microsoft
  - Splunk
products:
  - Office 365
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
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
  - title: O365 Advanced Audit Disabled via Management Activity
    description: Detects when O365 advanced audit is disabled for a user through a change in user license.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloud
      - o365
  - title: O365 Advanced Audit Disabled - Specific Plan Name
    description: Detects when O365 advanced audit is disabled based on the specific plan name in the event details.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloud
      - o365
rules_count: 2
---

This analytic detects instances where the O365 advanced audit is disabled for a specific user within an Office 365 tenant. It leverages O365 audit logs, specifically focusing on events related to audit license changes within Azure Active Directory workloads. Disabling the O365 advanced audit is a significant security concern, as it removes critical logging and visibility into user and administrator activities. Attackers could exploit this gap to operate with a reduced risk of detection. The activity is identified via the "Change user license." operation and the presence of "*M365_ADVANCED_AUDITING*" in the DisabledPlans field of the audit logs. The source is the Splunk ES Content Update (ESCU) with the ID 49862dd4-9cb2-4c48-a542-8c8a588d9361.

## Attack Chain

1.  The attacker gains initial access to a privileged account with sufficient permissions to modify user licenses within the Office 365 tenant.
2.  The attacker uses the privileged account to navigate to the Azure Active Directory or Microsoft 365 admin center.
3.  The attacker modifies the license configuration for a target user account.
4.  Specifically, the attacker disables the "M365_ADVANCED_AUDITING" plan for the target user, which stops the collection of advanced audit logs.
5.  The system records an O365 management activity event with Operation="Change user license." and the DisabledPlans containing "M365_ADVANCED_AUDITING".
6.  With advanced auditing disabled, the attacker performs malicious activities within the target user's account (e.g., data access, data exfiltration, sending phishing emails).
7.  These malicious actions are not fully logged or audited due to the disabled advanced auditing, thus reducing the chances of detection.

## Impact

Disabling advanced auditing can blind security teams to malicious actions. Attackers could operate within the user's mailbox or account with reduced risk of detection, potentially leading to unauthorized data access, data exfiltration, or account compromise. This can lead to significant data breaches, financial losses, and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect instances of disabled O365 advanced auditing based on `o365_management_activity` events.
*   Investigate any detected instances of disabled advanced auditing to determine if the change was authorized and legitimate.
*   Monitor the O365 management activity logs for "Change user license" operations, focusing on changes to audit-related plans.
*   Implement alerting for changes to user license, especially those that disable audit features using the Sigma rule.

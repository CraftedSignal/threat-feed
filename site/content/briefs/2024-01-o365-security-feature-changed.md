---
title: O365 Security Feature Modification
slug: 2024-01-o365-security-feature-changed
description: Attackers modify or disable Office 365 advanced security settings, such as AntiPhish, SafeLink, SafeAttachment, or Malware policies, to evade detection and operate with reduced risk within the target tenant.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - o365
  - email_security
  - defense_evasion
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
  - https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: O365 Email Security Feature Disabled
    description: Detects when O365 advanced security settings are disabled within the Office 365 tenant.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1562.008
    data_sources:
      - webserver
      - linux
  - title: O365 Email Security Feature Set
    description: Detects when O365 advanced security settings are set (created or modified) within the Office 365 tenant.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1562.008
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Attackers may target Office 365 security settings to weaken defenses and operate with impunity inside the tenant. By disabling or modifying features like AntiPhish, SafeLink, SafeAttachment, and Malware policies, attackers reduce the chances of their malicious activities being detected. This allows them to conduct unauthorized data access, data exfiltration, account compromise, and other malicious actions without triggering alerts or leaving a clear audit trail. These modifications can persist over time, enabling long-term access and control within the compromised environment. The modifications leave evidence in the Office 365 Management Activity logs, which defenders can monitor for suspicious changes.

## Attack Chain

1.  Initial Access: The attacker gains initial access to an account with sufficient privileges to modify O365 security settings, potentially through credential theft or phishing (not detailed in source).
2.  Privilege Escalation (if needed): If the compromised account lacks the necessary permissions, the attacker attempts to escalate privileges within the O365 tenant.
3.  Discovery: The attacker uses the compromised account to explore the O365 environment and identify available security settings that can be modified or disabled.
4.  Disable Security Features: The attacker disables or modifies key security features, such as AntiPhish, SafeLink, SafeAttachment, and Malware policies, using O365 management tools or PowerShell cmdlets (e.g., Set-AntiPhishPolicy).
5.  Persistence: By weakening security controls, the attacker establishes a persistent presence within the O365 tenant, reducing the likelihood of detection.
6.  Data Exfiltration/Lateral Movement: With security features disabled, the attacker can move laterally within the environment, access sensitive data, and exfiltrate it without triggering security alerts.
7.  Cover Tracks: The attacker may attempt to delete or modify audit logs to further conceal their activities, though this is not directly described in the source.

## Impact

Successful modification of O365 security features can lead to significant damage, including unauthorized access to sensitive data, data exfiltration, account compromise, and further malicious activities within the tenant. The reduction in security monitoring creates a window of opportunity for attackers to conduct a wide range of attacks without being detected, leading to potential financial losses, reputational damage, and compliance violations.

## Recommendation

*   Deploy the Sigma rules provided below to your SIEM and tune them for your environment to detect changes to O365 email security features based on the `o365_management_activity` logs.
*   Investigate any alerts triggered by the Sigma rules to determine the legitimacy of the changes and the potential impact on the security posture of the O365 tenant.
*   Monitor the Office 365 Universal Audit Log for suspicious activities related to the modification of security settings as outlined in the `search` query in the brief.
*   Review and harden O365 role-based access controls (RBAC) to limit the accounts that can modify security settings, following Microsoft's security recommendations at https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults.

---
title: GitHub Enterprise 2FA Requirement Disabled
slug: 2024-01-03-github-2fa-disable
description: The disabling of two-factor authentication (2FA) in GitHub Enterprise, detected via audit logs, weakens account security and increases the risk of account takeover and supply chain compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - 2fa
  - defense-evasion
vendors:
  - GitHub
  - Splunk
products:
  - GitHub Enterprise
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise 2FA Disabled by User
    description: Detects when a user disables the two-factor authentication requirement in GitHub Enterprise via the web interface.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise 2FA Disable via API
    description: Detects when a user disables the two-factor authentication requirement in GitHub Enterprise via the API.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This analytic detects the disabling of two-factor authentication (2FA) requirements within GitHub Enterprise environments. The detection focuses on monitoring GitHub Enterprise audit logs, specifically searching for events related to changes in 2FA requirements. The activity is identified by tracking actor details, organization information, and associated metadata within the logs. Successfully disabling 2FA increases the risk of account takeover, unauthorized access to sensitive code, and potential compromise of the software supply chain. This activity can be a precursor to broader malicious activities, such as data exfiltration or code injection.

## Attack Chain

1. An attacker gains initial access to a GitHub Enterprise account with administrative privileges.
2. The attacker navigates to the organization or business settings within GitHub Enterprise.
3. The attacker locates the two-factor authentication (2FA) settings.
4. The attacker disables the 2FA requirement for the organization or specific user groups. This action is logged in the GitHub Enterprise audit logs.
5. With 2FA disabled, the attacker attempts to compromise user accounts through password-based attacks such as credential stuffing or brute-forcing.
6. Upon successfully compromising an account, the attacker gains unauthorized access to repositories and other resources.
7. The attacker may then exfiltrate sensitive code, inject malicious code, or modify repository settings.
8. The attacker achieves their objective, which could be intellectual property theft, supply chain compromise, or disruption of services.

## Impact

Disabling 2FA requirements significantly increases the risk of unauthorized access to GitHub Enterprise organizations and repositories. This can lead to account takeovers, data breaches, intellectual property theft, and supply chain attacks. The compromise of sensitive code can result in significant financial losses, reputational damage, and legal liabilities. This affects organizations using GitHub Enterprise for software development and code management.

## Recommendation

*   Enable and deploy the provided Sigma rule `GitHub Enterprise 2FA Disabled by User` to detect instances where 2FA requirements are disabled via the GitHub Enterprise audit logs.
*   Enable and deploy the provided Sigma rule `GitHub Enterprise 2FA Disable via API` to detect instances where 2FA requirements are disabled via the GitHub Enterprise API audit logs.
*   Investigate any detected instances of disabled 2FA to determine the actor involved and the scope of the impact.
*   Enforce multi-factor authentication across all GitHub Enterprise accounts and user groups to mitigate the risk of account compromise.
*   Regularly review GitHub Enterprise audit logs for suspicious activity, including changes to security settings and access controls, as outlined in the references.

---
title: GitHub Enterprise Dependabot Disablement
slug: 2024-01-github-dependabot-disable
description: An attacker disables Dependabot in a GitHub repository to prevent automatic vulnerability detection, potentially leading to exploitation of unpatched dependencies and supply chain compromise.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - dependabot
  - supply-chain
  - defense-evasion
vendors:
  - GitHub
products:
  - GitHub Enterprise
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/github_enterprise_disable_dependabot.yml
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise Dependabot Disabled
    description: Detects when a user disables Dependabot in a GitHub repository, which could indicate an attempt to prevent vulnerability detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Suspicious User Agent - Dependabot Disable
    description: Detects Dependabot disable action with a suspicious user agent, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Dependabot Disabled by Bot Account
    description: Alert when Dependabot is disabled by an automated bot account, which could signal unusual behavior.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - linux
rules_count: 3
---

This threat brief addresses the disabling of Dependabot within a GitHub Enterprise environment. Dependabot is a security feature that automatically identifies and helps fix vulnerabilities in project dependencies. Attackers may disable Dependabot to prevent the automatic detection of vulnerable dependencies, allowing them to exploit these vulnerabilities undetected. This action can serve as a precursor to more extensive supply chain attacks. This detection leverages GitHub Enterprise audit logs to identify instances where Dependabot functionality is disabled. The scope of targeting involves any GitHub Enterprise repository where Dependabot is active.

## Attack Chain

1. **Initial Access:** An attacker gains access to a GitHub account with sufficient privileges to modify repository settings.
2. **Reconnaissance:** The attacker identifies a target repository that utilizes Dependabot for dependency vulnerability scanning.
3. **Privilege Escalation (if necessary):** The attacker escalates privileges within the GitHub repository to gain the necessary permissions to modify settings.
4. **Configuration Change:** The attacker navigates to the repository settings and disables the Dependabot feature, specifically repository vulnerability alerts.
5. **Persistence:** The attacker may create backdoors or other persistent access mechanisms to maintain access to the compromised repository.
6. **Exploitation:** The attacker introduces or exploits existing vulnerabilities in the repository's dependencies, now unchecked by Dependabot.
7. **Lateral Movement:** The attacker uses the compromised repository as a stepping stone to access other internal systems or repositories.
8. **Impact:** The attacker exfiltrates sensitive data, injects malicious code into software builds, or disrupts services, leading to a supply chain compromise.

## Impact

Successful exploitation following Dependabot disablement can lead to significant damage, including data theft, malicious code injection, and service disruption. The number of affected victims depends on the scope of the compromised repository and its dependencies. Targeted sectors could include software development, technology, and any industry reliant on the affected software. The impact could extend beyond the immediate organization, affecting downstream customers and partners.

## Recommendation

*   Enable and actively monitor GitHub Enterprise audit logs, specifically for `repository_vulnerability_alerts.disable` events, as outlined in the documentation ([https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk)).
*   Deploy the provided Sigma rule to your SIEM to detect Dependabot disablement events in real-time.
*   Investigate any alerts generated by the Sigma rule to determine the legitimacy of the Dependabot disablement action.
*   Implement multi-factor authentication (MFA) for all GitHub accounts, especially those with administrative privileges.
*   Enforce the principle of least privilege for GitHub repository access to minimize the impact of compromised accounts.

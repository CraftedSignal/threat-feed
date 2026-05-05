---
title: GitHub Enterprise Dependabot Disablement
slug: 2024-01-github-dependabot-disable
description: Attackers may disable Dependabot in GitHub repositories to prevent automatic vulnerability detection and remediation, potentially leading to exploitation of unpatched dependencies.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github
  - supply-chain
  - dependabot
  - vulnerability-management
vendors:
  - GitHub
  - Splunk
products:
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
  - title: GitHub Enterprise - Dependabot Disabled
    description: Detects when a user disables Dependabot security features in a GitHub repository.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1195
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise - Dependabot Disabled (Detailed)
    description: Detects when a user disables Dependabot security features in a GitHub repository based on user agent and actor.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1195
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief addresses the risk associated with disabling Dependabot in GitHub Enterprise environments. Dependabot is a feature that automatically identifies and helps fix security vulnerabilities in project dependencies. When Dependabot is disabled, repositories become more vulnerable to attacks that exploit known security flaws in those dependencies. This could be an intentional action by a malicious insider or a compromised account attempting to weaken an organization's security posture. The activity is identified via GitHub Enterprise audit logs that record configuration changes related to Dependabot functionality. This is a critical security concern because it can lead to supply chain attacks where attackers leverage vulnerable dependencies to compromise systems and data.

## Attack Chain

1. **Initial Access:** An attacker gains unauthorized access to a GitHub Enterprise account with repository administration privileges.
2. **Reconnaissance:** The attacker identifies repositories with valuable code or sensitive data.
3. **Disable Security Features:** The attacker disables Dependabot for the chosen repository using the GitHub web interface or API, specifically triggering the `repository_vulnerability_alerts.disable` action.
4. **Dependency Introduction/Modification:** The attacker introduces or modifies project dependencies to include vulnerable versions without Dependabot's automatic alerts.
5. **Vulnerability Exploitation:** The attacker exploits the known vulnerabilities present in the compromised dependencies.
6. **Lateral Movement:** The attacker uses the compromised system as a pivot to access other internal systems or data.
7. **Data Exfiltration/System Compromise:** The attacker exfiltrates sensitive data or gains complete control of the compromised system.

## Impact

Disabling Dependabot can lead to significant security breaches, as it removes a critical layer of defense against vulnerable dependencies. A successful attack could result in data theft, code execution, and complete system compromise. The impact is amplified in supply chain attacks, where a single vulnerable component can affect multiple downstream users and systems. While the exact number of potential victims is hard to quantify, any GitHub Enterprise user disabling Dependabot poses a risk to the security of their projects and the broader ecosystem that depends on them.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect instances where Dependabot is disabled in your GitHub Enterprise environment.
*   Investigate any detected instances of Dependabot being disabled, correlating with other suspicious activity from the same user or IP address.
*   Review GitHub Enterprise audit logs for `repository_vulnerability_alerts.disable` events to proactively identify disabled Dependabot instances.
*   Enforce multi-factor authentication (MFA) for all GitHub Enterprise accounts, especially those with administrative privileges, to mitigate unauthorized access (T1195).

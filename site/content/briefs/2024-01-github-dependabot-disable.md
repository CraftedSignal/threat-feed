---
title: GitHub Dependabot Disabled to Evade Vulnerability Detection
slug: 2024-01-github-dependabot-disable
description: An attacker disables GitHub Dependabot security features to prevent automatic detection of vulnerable dependencies, potentially leading to code execution, data theft, or other compromises through the software supply chain.
date: "2024-01-03T12:00:00Z"
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
  - GitHub
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
  - https://splunk.github.io/splunk-add-on-for-github-audit-log-monitoring/Install/
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
rules:
  - title: Detect GitHub Dependabot Disable
    description: Detects when a user disables Dependabot security features within a GitHub repository.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - supply_chain_compromise
    techniques:
      - T1195
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub User Agent Anomalies for Dependabot Disable
    description: Detects unusual user agents associated with Dependabot disabling actions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - supply_chain_compromise
    techniques:
      - T1195
      - T1562.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief addresses the risk associated with the disabling of Dependabot within GitHub organizations. Dependabot is a security feature that automatically identifies and helps fix vulnerabilities in a project's dependencies. An attacker may disable Dependabot to prevent the automatic detection of vulnerable dependencies, which would allow them to exploit known vulnerabilities that would otherwise be patched. This action can be a precursor to supply chain attacks where attackers exploit vulnerable dependencies. This activity is detected by monitoring GitHub Enterprise logs for configuration changes related to disabling Dependabot functionality. Identifying the disabling of security features like Dependabot is critical for SOC teams as it may lead to severe consequences if vulnerabilities remain unpatched, potentially leading to code execution, data theft, or other compromises through the software supply chain. The detection logic is based on logs from the Splunk Add-on for Github.

## Attack Chain

1.  **Initial Access:** An attacker gains access to a GitHub account with sufficient privileges to modify repository settings, potentially through compromised credentials or insider access.
2.  **Privilege Escalation (If Necessary):** The attacker escalates privileges within the GitHub organization to gain the ability to modify repository settings.
3.  **Discovery:** The attacker identifies target repositories within the GitHub organization that are suitable for supply chain attacks.
4.  **Disable Dependabot:** The attacker disables Dependabot for the targeted repositories by modifying the repository settings using the GitHub web interface or API. The action triggers a `repository_vulnerability_alerts.disable` event in the GitHub audit logs.
5.  **Introduce Vulnerable Dependency:** The attacker introduces a vulnerable dependency into the target repository, either by directly modifying the project's dependency files or by exploiting existing vulnerabilities to inject malicious code.
6.  **Exploit Vulnerability:** The attacker exploits the introduced vulnerability to gain unauthorized access to systems or data, potentially leading to code execution or data theft.
7.  **Lateral Movement:** The attacker uses the compromised system to move laterally within the organization's network, gaining access to additional systems and data.
8.  **Exfiltration/Impact:** The attacker exfiltrates sensitive data or causes damage to systems, achieving their ultimate objective.

## Impact

Successful exploitation following the disabling of Dependabot can lead to significant consequences, including data breaches, code execution on critical systems, and supply chain compromise. The number of affected repositories and the severity of the vulnerabilities determine the scale of the impact. Sectors that heavily rely on open-source dependencies, such as software development, finance, and healthcare, are particularly vulnerable. If successful, this attack can result in significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the Sigma rule `Detect GitHub Dependabot Disable` to your SIEM and tune it for your environment, focusing on the `github_organizations` data source to detect the disabling of Dependabot.
*   Monitor GitHub Organizations Audit Logs for `repository_vulnerability_alerts.disable` events, as indicated in the `search` query, to identify potential unauthorized modifications.
*   Implement multi-factor authentication (MFA) for all GitHub accounts, especially those with administrative privileges, to prevent unauthorized access as part of the initial access stage.
*   Review user access and permissions within the GitHub organization to ensure that only authorized users have the ability to modify repository settings and prevent privilege escalation.

---
title: GitHub Organization Repository Deletion
slug: 2024-01-github-repo-delete
description: Anomalous deletion of a GitHub organization repository can indicate malicious activity aimed at destroying source code, intellectual property, or evidence of compromise, potentially stemming from account compromise, insider threats, or business disruption attempts.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - repository
  - deletion
  - impact
vendors:
  - GitHub
products:
  - GitHub Organizations
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://splunk.github.io/splunk-add-on-for-github-audit-log-monitoring/Install/
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
rules:
  - title: GitHub Organization Repository Deletion Detected
    description: Detects when a repository is deleted within a GitHub organization based on audit logs.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 1
---

This threat brief focuses on the anomalous deletion of repositories within GitHub organizations, an activity that can have severe consequences. The core concern is that a malicious actor, whether an external attacker with compromised credentials or a malicious insider, may deliberately delete repositories to destroy source code, intellectual property, or even evidence of a prior compromise. The behavior is detected by monitoring GitHub Organizations audit logs for repository deletion events (vendor_action=repo.destroy). The deletion of repositories may lead to permanent data loss if backups are not maintained. This activity may be associated with attempts to disrupt business operations. Early detection of such events is crucial, allowing security teams to investigate potential compromises and initiate recovery procedures, minimizing potential damage.

## Attack Chain

1.  **Initial Access:** The attacker gains unauthorized access to a GitHub organization account. This could be through compromised credentials (phishing, password reuse), or by exploiting a vulnerability in a service integrated with GitHub.
2.  **Privilege Escalation (if needed):** The attacker elevates their privileges within the GitHub organization to gain sufficient permissions to delete repositories.
3.  **Reconnaissance:** The attacker identifies valuable or critical repositories for deletion, potentially focusing on those containing sensitive data, core application code, or incident response documentation.
4.  **Disable Security Controls (Optional):** The attacker attempts to disable or circumvent security controls within GitHub or integrated security tools to avoid detection.
5.  **Repository Deletion:** The attacker executes the repository deletion command, either through the GitHub web interface or the GitHub API. This generates an audit log event (`vendor_action=repo.destroy`).
6.  **Obfuscation/Cleanup:** The attacker attempts to cover their tracks by deleting audit logs, modifying access logs, or removing any traces of their activity within the GitHub environment.
7.  **Impact:** The targeted repository is permanently deleted, resulting in the loss of source code, documentation, and project history. This can disrupt development workflows, lead to financial losses, and compromise intellectual property.

## Impact

The impact of a successful repository deletion attack can be significant. Organizations can experience a loss of intellectual property, disruption to development workflows, and potential financial losses resulting from the lost work and the cost of recovery. In severe cases, the deletion of critical repositories could halt operations and damage the organization's reputation. The number of affected repositories and the severity of the impact depend on the attacker's objectives and the organization's backup and recovery capabilities.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM and tune them to your specific GitHub organization to detect anomalous repository deletion activity based on `vendor_action=repo.destroy`.
*   Implement multi-factor authentication (MFA) for all GitHub accounts, especially those with administrative privileges, to mitigate the risk of compromised credentials referenced in the attack chain.
*   Regularly review and audit GitHub organization access controls and permissions to identify and remediate any excessive or unnecessary privileges, preventing privilege escalation.
*   Implement a robust backup and recovery strategy for GitHub repositories, including regular backups and tested restoration procedures, ensuring quick recovery in case of a repository deletion attack.
*   Monitor GitHub Organizations audit logs for suspicious activity, including unusual login patterns, unauthorized permission changes, and unexpected API calls.

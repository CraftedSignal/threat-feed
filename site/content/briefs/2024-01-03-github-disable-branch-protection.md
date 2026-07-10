---
title: GitHub Enterprise Classic Branch Protection Disabled
slug: 2024-01-03-github-disable-branch-protection
description: An attacker disables classic branch protection rules in GitHub Enterprise, potentially to bypass code review and security controls leading to code tampering, vulnerability introduction, or supply chain compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - branch-protection
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
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise Disable Classic Branch Protection Rule
    description: Detects when a classic branch protection rule is disabled in GitHub Enterprise by monitoring audit logs for 'protected_branch.destroy' events.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Branch Protection Rule Modification by Non-Admin
    description: Detects when a classic branch protection rule is modified or deleted by a non-administrator account, which can indicate potential privilege escalation or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This threat brief focuses on the disabling of classic branch protection rules within GitHub Enterprise environments.  The disabling of these rules can allow attackers to bypass established code review processes and security controls. By monitoring GitHub Enterprise audit logs for events indicating the removal of branch protections, security teams can identify potentially malicious activity.  The impact of this activity can range from the introduction of vulnerabilities and malicious code to a full compromise of the software supply chain integrity.  This activity could be a precursor to a larger attack, where an adversary disables security measures before injecting malicious code. This brief provides detection and response recommendations for this specific threat.

## Attack Chain

1.  The attacker compromises a GitHub Enterprise account with sufficient privileges to modify branch protection rules.
2.  The attacker authenticates to the GitHub Enterprise instance using the compromised account.
3.  The attacker navigates to the settings of a target repository where branch protection rules are enabled.
4.  The attacker identifies and removes a classic branch protection rule. This action generates an audit log event with the action `protected_branch.destroy`.
5.  The attacker makes unauthorized code changes, potentially introducing vulnerabilities or malicious code.
6.  The attacker commits and pushes these changes directly to the protected branch, bypassing code review.
7.  The malicious code is deployed into production environments, impacting users and systems.

## Impact

Disabling branch protection rules in GitHub Enterprise allows attackers to bypass security controls, potentially leading to code tampering, the introduction of vulnerabilities, or malicious code injection. This can compromise the integrity of the software supply chain. A successful attack could lead to data breaches, service disruptions, or reputational damage.

## Recommendation

*   Enable and monitor GitHub Enterprise audit logs, specifically events related to `protected_branch.destroy`, as this action indicates the removal of branch protection rules.
*   Deploy the provided Sigma rule `GitHub Enterprise Disable Classic Branch Protection Rule` to your SIEM to detect when branch protection rules are disabled.
*   Investigate any detected instances of disabled branch protection rules, focusing on the actor and the affected repository.
*   Review user access controls and enforce multi-factor authentication (MFA) to prevent account compromises.

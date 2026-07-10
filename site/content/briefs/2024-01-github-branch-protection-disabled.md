---
title: GitHub Classic Branch Protection Rule Disabled
slug: 2024-01-github-branch-protection-disabled
description: Detection of classic branch protection rules being disabled in GitHub Organizations, potentially indicating an attempt to bypass security controls and inject malicious code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - branch_protection
  - defense_evasion
  - code_tampering
vendors:
  - GitHub
products:
  - GitHub
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
  - https://splunk.github.io/splunk-add-on-for-github-audit-log-monitoring/Install/
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
rules:
  - title: GitHub Organizations Classic Branch Protection Disabled
    description: Detects when a classic branch protection rule is disabled in GitHub Organizations.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub Organizations Classic Branch Protection Disabled (Audit Logs)
    description: Detects when a classic branch protection rule is disabled by monitoring Github Audit Logs
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This brief addresses the threat of disabled classic branch protection rules within GitHub Organizations. This activity is detected by monitoring GitHub Organizations audit logs for events related to the removal of branch protections. The disabling of these rules can be a critical indicator of malicious activity, suggesting attempts to bypass code review processes and security controls. An attacker might disable branch protection to facilitate the direct injection of unauthorized code changes or backdoors into protected branches. This can be a step in a larger attack chain where security controls are first disabled to allow for subsequent malicious actions. This analytic specifically focuses on classic branch protection rules within GitHub Organizations.

## Attack Chain

1.  The attacker gains initial access to a GitHub account with sufficient privileges to modify branch protection rules.
2.  The attacker authenticates to the GitHub organization and navigates to the repository settings.
3.  The attacker identifies a target branch with classic branch protection rules enabled.
4.  The attacker disables the classic branch protection rules for the target branch, generating a `protected_branch.destroy` event in the audit logs.
5.  The attacker commits and pushes unauthorized code changes, bypassing code review and other protection mechanisms.
6.  The malicious code is merged into the protected branch, potentially introducing vulnerabilities or backdoors into the codebase.
7.  The attacker may attempt to further obfuscate their actions by deleting audit logs or modifying other security settings (not covered in this specific detection).

## Impact

The disabling of classic branch protection rules can have severe consequences, leading to potential code tampering, bypass of security reviews, introduction of vulnerabilities or malicious code, and ultimately, a compromise of software supply chain integrity. The impact includes the potential for unauthorized code changes being introduced into production environments, leading to data breaches, service disruptions, or other security incidents. The number of victims depends on the scope of the affected repository and the criticality of the compromised code.

## Recommendation

*   Deploy the following Sigma rule to your SIEM to detect instances of disabled classic branch protection rules and tune for your environment.
*   Investigate any detected instances of disabled branch protection rules, focusing on the actor, repository, and timeline of events.
*   Implement multi-factor authentication (MFA) for all GitHub accounts, especially those with administrative privileges, to reduce the risk of unauthorized access.
*   Regularly review and audit GitHub organization settings, including branch protection rules, to ensure they are properly configured and enforced.
*   Utilize the Splunk Add-on for Github to ingest GitHub Organizations audit logs as specified in the "how_to_implement" section to ensure proper data ingestion for the detection rule.

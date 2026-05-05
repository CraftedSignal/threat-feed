---
title: GitHub Enterprise Classic Branch Protection Rule Disabled
slug: 2024-01-github-branch-protection-disabled
description: Detection of disabled classic branch protection rules in GitHub Enterprise, indicating potential bypass of code review and security controls, leading to unauthorized code changes and supply chain compromise.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github
  - branch_protection
  - supply_chain
vendors:
  - GitHub
  - Splunk
products:
  - GitHub Enterprise
  - github.com
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-splunk
rules:
  - title: GitHub Enterprise Disable Classic Branch Protection Rule
    description: Detects when a classic branch protection rule is disabled in GitHub Enterprise. This activity can indicate an attempt to bypass security controls and introduce malicious code.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Disable Classic Branch Protection Rule (User Agent)
    description: Detects when a classic branch protection rule is disabled in GitHub Enterprise based on the user agent. This activity can indicate an attempt to bypass security controls and introduce malicious code.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub Enterprise Disable Classic Branch Protection Rule (Process Creation)
    description: Detects when a classic branch protection rule is disabled in GitHub Enterprise by monitoring the command line arguments of a process.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This brief focuses on the detection of disabled classic branch protection rules within a GitHub Enterprise environment. The detection is based on monitoring GitHub Enterprise audit logs for events related to the removal of branch protections. Attackers may disable these rules to bypass code review processes and introduce malicious code or vulnerabilities directly into protected branches. This action can be part of a larger attack, where adversaries first weaken security controls before injecting malicious content. Identifying and responding to these events is crucial for maintaining the integrity and security of the software supply chain. This analytic is sourced from Splunk's security content and is designed to run on GitHub Enterprise audit logs ingested into Splunk.

## Attack Chain

1. An attacker gains unauthorized access to a GitHub Enterprise account with sufficient privileges.
2. The attacker navigates to the repository settings within the GitHub Enterprise instance.
3. The attacker identifies the classic branch protection rules configured for a target branch.
4. The attacker disables one or more of these branch protection rules, such as code review enforcement or restrictions on force pushes. This generates a `protected_branch.destroy` event in the audit logs.
5. The attacker commits and pushes unauthorized or malicious code directly to the protected branch, bypassing established security controls.
6. The malicious code is merged into the main branch, potentially affecting production systems or downstream consumers of the code.
7. The attacker may attempt to cover their tracks by deleting audit logs or manipulating other security controls.

## Impact

The impact of disabled branch protection rules can be significant. Successful exploitation can lead to the introduction of vulnerabilities, malicious code, or backdoors into the software supply chain. This can result in data breaches, system compromise, and reputational damage. The number of affected systems and the extent of the damage depend on the scope and nature of the malicious code injected. The targets are GitHub Enterprise organizations that rely on branch protection rules to maintain code quality and security.

## Recommendation

*   Enable GitHub Enterprise Audit log streaming to a SIEM or log management solution to capture `protected_branch.destroy` events as described in the GitHub Enterprise documentation.
*   Deploy the Sigma rule `GitHub Enterprise Disable Classic Branch Protection Rule` to detect instances where branch protection rules are disabled and tune it for your environment.
*   Investigate any alerts generated by the Sigma rule, focusing on the `actor`, `repo`, and `user_agent` fields to understand the context of the event.
*   Implement multi-factor authentication (MFA) for all GitHub Enterprise accounts, especially those with administrative privileges.
*   Regularly review and audit GitHub Enterprise configurations to ensure that branch protection rules are properly configured and enforced.

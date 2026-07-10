---
title: GitHub Organizations Branch Ruleset Deletion
slug: 2024-01-03-github-branch-ruleset-deletion
description: Detection of branch ruleset deletion in GitHub Organizations, indicating potential attempts to bypass security controls and inject malicious code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - supply-chain
  - defense-evasion
vendors:
  - GitHub
products:
  - GitHub Organizations
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0009
    tactic_name: Supply Chain Compromise
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://splunk.github.io/splunk-add-on-for-github-audit-log-monitoring/Install/
  - https://www.googlecloudcommunity.com/gc/Community-Blog/Monitoring-for-Suspicious-GitHub-Activity-with-Google-Security/ba-p/763610
rules:
  - title: GitHub Organizations Delete Branch Ruleset
    description: Detects when branch rulesets are deleted in GitHub Organizations, potentially indicating attempts to bypass security controls.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1195
      - T1562.001
    data_sources:
      - webserver
      - linux
  - title: GitHub Organizations Branch Ruleset Modification
    description: Detects modifications to branch rulesets in GitHub Organizations, which could indicate malicious attempts to weaken security controls.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1195
      - T1562.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This brief focuses on the detection of deleted branch rulesets within GitHub Organizations. Threat actors may attempt to disable or delete these rulesets to bypass code review requirements and security controls. This activity can be an indicator of malicious intent, potentially leading to the injection of unauthorized code changes or backdoors into protected branches. The detection mechanism involves monitoring GitHub Organizations audit logs for specific events related to branch ruleset deletion. Identifying these events allows for timely intervention to prevent code tampering and maintain software supply chain integrity. This is crucial for organizations relying on GitHub for code management and collaboration.

## Attack Chain

1.  **Initial Access:** An attacker gains access to a GitHub account with sufficient privileges to manage branch rulesets.
2.  **Reconnaissance:** The attacker identifies target repositories and their associated branch rulesets.
3.  **Privilege Escalation (if necessary):** The attacker elevates their privileges within the organization to gain the ability to modify or delete rulesets.
4.  **Defense Evasion:** The attacker deletes a branch ruleset, effectively disabling the security controls it provided (e.g., code review, preventing force pushes).
5.  **Code Injection:** The attacker pushes unauthorized code changes, potentially containing malicious code or backdoors, directly to a protected branch.
6.  **Persistence (Optional):** The attacker may implement persistence mechanisms within the injected code to maintain unauthorized access.
7.  **Impact:** The malicious code compromises the software supply chain, potentially affecting downstream users and systems.

## Impact

The deletion of branch rulesets can have significant consequences, leading to code tampering, bypass of security reviews, and the introduction of vulnerabilities or malicious code. If successful, this can compromise the integrity of the software supply chain, impacting potentially thousands of users and systems relying on the affected code. The incident could result in data breaches, financial losses, and reputational damage.

## Recommendation

*   Enable GitHub Organizations audit logs and ingest them into your SIEM to allow for monitoring of branch ruleset deletion events.
*   Deploy the Sigma rule `GitHub Organizations Delete Branch Ruleset` to detect when branch rulesets are deleted in GitHub Organizations.
*   Investigate any alerts triggered by the Sigma rule, focusing on the `actor`, `repo`, and `ruleset_name` to determine the legitimacy of the action.
*   Implement multi-factor authentication (MFA) for all GitHub accounts to reduce the risk of unauthorized access (Reference: GitHub documentation).
*   Regularly review and audit GitHub Organizations permissions to ensure that users only have the necessary privileges (Reference: GitHub documentation).

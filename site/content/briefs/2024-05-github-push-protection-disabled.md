---
title: GitHub Push Protection Disabled
slug: 2024-05-github-push-protection-disabled
description: An administrator has disabled the GitHub push protection feature, potentially allowing secrets and other sensitive information to be pushed to repositories.
date: "2024-05-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - attack.defense-impairment
  - attack.t1685
vendors:
  - GitHub
products:
  - GitHub Enterprise Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/push-protection-for-repositories-and-organizations
  - https://thehackernews.com/2024/03/github-rolls-out-default-secret.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/application/github/audit/github_push_protection_disabled.yml
rules:
  - title: GitHub Push Protection Disabled
    description: Detects if the push protection feature is disabled for an organization, enterprise, repositories or custom pattern rules.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - github
      - audit
  - title: GitHub Push Protection Custom Pattern Disabled
    description: Detects when a custom pattern for push protection is disabled within GitHub.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - github
      - audit
rules_count: 2
---

The GitHub push protection feature is designed to prevent secrets and sensitive information from being committed to repositories. Disabling this feature, whether at the organization, enterprise, or repository level, significantly increases the risk of accidental or intentional exposure of credentials, API keys, and other sensitive data. This can lead to unauthorized access, data breaches, and other security incidents. The actions detected can originate from administrative accounts or potentially compromised accounts with administrative privileges. This brief focuses on detecting the disabling of push protection, allowing security teams to respond and remediate the configuration.

## Attack Chain

1.  An attacker gains unauthorized access to a GitHub account with administrative privileges, or a legitimate administrator performs the action.
2.  The attacker navigates to the organization, enterprise, or repository settings in GitHub.
3.  The attacker locates the "Secret scanning" or "Push protection" configuration section.
4.  The attacker disables the push protection feature for the organization, enterprise, or specific repositories. This can be done via the GitHub UI or API.
5.  GitHub audit logs record the event with the actions `business_secret_scanning_custom_pattern_push_protection.disabled`, `business_secret_scanning_push_protection.disable`, `org.secret_scanning_custom_pattern_push_protection_disabled`, etc..
6.  Developers unknowingly or intentionally commit code containing secrets or sensitive data to the affected repositories.
7.  The secrets are pushed to the remote repository without being blocked by push protection.
8.  The exposed secrets can be discovered by malicious actors, leading to account compromise, data breaches, or other security incidents.

## Impact

Disabling push protection can lead to the exposure of sensitive information such as API keys, passwords, and other credentials within GitHub repositories. This exposure can lead to account compromise, unauthorized access to systems and data, and potentially significant financial and reputational damage. The number of affected repositories and the severity of the impact depends on the scope of the push protection disabling and the types of secrets committed to the repositories.

## Recommendation

*   Deploy the Sigma rule "Github Push Protection Disabled" to your SIEM and tune for your environment to detect when push protection is disabled.
*   Investigate any detected instances of push protection being disabled in the GitHub audit logs (logsource: github, service: audit) to verify the legitimacy of the action.
*   Enforce multi-factor authentication (MFA) for all GitHub accounts, especially those with administrative privileges, to prevent unauthorized access.
*   Regularly review and audit GitHub organization and repository settings to ensure that push protection is enabled and properly configured.

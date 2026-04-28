---
title: GitHub Secret Scanning Feature Disabled
slug: 2024-07-github-secret-scanning-disabled
description: Detection of the disabling of GitHub secret scanning at the business or repository level, potentially increasing the risk of exposed credentials and secrets.
date: "2024-07-19T00:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - attack.defense-impairment
  - attack.t1685
vendors:
  - Github
products:
  - Github
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/about-secret-scanning
rules:
  - title: Github Secret Scanning Feature Disabled
    description: Detects if the secret scanning feature is disabled for an enterprise or repository.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - github
      - audit
  - title: Github Secret Scanning New Repositories Disabled
    description: Detects if the secret scanning feature is disabled for new repositories within an enterprise.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - github
      - audit
rules_count: 2
---

The disabling of GitHub's secret scanning feature represents a significant security risk. Secret scanning is a critical control that prevents sensitive information, such as API keys, credentials, and tokens, from being committed to repositories. An attacker who gains administrative access to a GitHub organization or repository could disable this feature to facilitate the undetected introduction of secrets into the codebase. This action undermines the organization's security posture, creating opportunities for unauthorized access and data breaches. The activity is logged via GitHub audit logs, providing an opportunity for detection. This brief focuses on detecting the actions that disable the secret scanning feature within GitHub.

## Attack Chain

1.  An attacker gains unauthorized access to a GitHub account with administrative privileges for either an organization or a specific repository.
2.  The attacker navigates to the security settings within the organization or repository.
3.  The attacker identifies the "Secret scanning" feature or related settings (e.g., "Secret scanning for new repositories").
4.  The attacker disables the secret scanning feature using the GitHub UI or API. This generates an audit log event.
5.  The attacker commits code containing secrets to the repository.
6.  Because secret scanning is disabled, the secrets are not detected or flagged by GitHub.
7.  The attacker leverages the committed secrets to gain unauthorized access to other systems or data.
8.  The attacker achieves their final objective, which could include data exfiltration, lateral movement, or service disruption.

## Impact

Disabling secret scanning can lead to the exposure of sensitive credentials within a codebase. If successful, attackers can leverage these exposed secrets to compromise systems, access sensitive data, and potentially cause significant financial and reputational damage. The number of affected repositories and the extent of the damage depend on the scope of the access the attacker gains and the criticality of the exposed secrets. This can affect any organization that uses Github for source code management.

## Recommendation

*   Deploy the "Github Secret Scanning Feature Disabled" Sigma rule to your SIEM to detect unauthorized disabling of the feature (logsource: github, service: audit).
*   Investigate any detected instances of secret scanning being disabled to determine if they were authorized administrative actions.
*   Enable audit log streaming to ensure the required logs are available (see logsource definition).
*   Review GitHub access controls to ensure that only authorized personnel have the ability to modify secret scanning settings.

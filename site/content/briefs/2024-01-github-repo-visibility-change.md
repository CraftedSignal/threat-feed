---
title: GitHub Private Repository Visibility Changed to Public
slug: 2024-01-github-repo-visibility-change
description: An adversary may change a private GitHub repository to public visibility to exfiltrate sensitive code or data, potentially indicating a compromise or unauthorized access, and immediately fork or mirror the repo to an external account to retain access and harvest embedded secrets.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - github
  - exfiltration
  - repository
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1020
    technique_name: Automated Exfiltration
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/exfiltration_github_private_repository_turned_public.toml
rules:
  - title: GitHub Private Repository Turned Public Visibility
    description: Detects when a private GitHub repository is changed to public visibility, potentially indicating exfiltration activity.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1567.001
    data_sources:
      - webserver
      - github
  - title: GitHub Repository Forked After Visibility Change
    description: Detects when a repository is forked shortly after its visibility is changed from private to public.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.001
    data_sources:
      - webserver
      - github
rules_count: 2
---

Attackers may compromise a GitHub account with repository access and change the visibility of private repositories to public. This allows them to exfiltrate code, data, and secrets contained within the repository. This change can be done through the GitHub UI or via the API. After making the repository public, the attacker may quickly fork or mirror the repository to an external account, ensuring they retain access even if the organization reverts the visibility change. This tactic is useful for attackers looking to steal proprietary code, intellectual property, or sensitive data stored in private repositories. The elastic rule "GitHub Private Repository Turned Public" detects this activity.

## Attack Chain

1. An attacker gains unauthorized access to a GitHub account with maintainer or owner privileges.
2. The attacker authenticates to GitHub using the compromised credentials or stolen API token.
3. The attacker modifies the visibility settings of a private repository to "public" via the GitHub UI or API.
4. GitHub's audit logs record the change in repository visibility (github.previous_visibility == "private" and github.visibility == "public").
5. The attacker immediately forks the now-public repository to an external account they control.
6. Alternatively, the attacker mirrors the repository to an external server or code hosting platform.
7. The attacker scans the repository history and current HEAD for sensitive information such as API keys, passwords, and cloud credentials.
8. The attacker uses the exfiltrated data to gain access to other systems or services, or sells the data to a third party.

## Impact

Changing a private GitHub repository to public can lead to the exposure of sensitive source code, proprietary algorithms, internal documentation, and credentials. If successful, attackers can gain unauthorized access to other systems and services, intellectual property theft, financial loss, and reputational damage. Exposed credentials, such as API keys and passwords, can be used to compromise cloud infrastructure, databases, and other internal resources. The severity depends on the sensitivity of the data stored in the repository and the speed of incident response.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect changes in GitHub repository visibility (github.previous_visibility == "private" and github.visibility == "public").
*   Review and harden GitHub access controls, including requiring multi-factor authentication (MFA) for all users, especially repository owners and maintainers.
*   Implement a process for regularly reviewing GitHub audit logs for suspicious activity, such as unexpected changes in repository visibility or permissions.
*   Enforce restrictions on forking of private repositories to prevent attackers from easily copying sensitive code to external accounts.
*   Enable GitHub secret scanning with push protection to prevent developers from accidentally committing secrets to repositories.
*   Rotate exposed credentials (cloud keys, API tokens, SSH keys) invalidated compromised service accounts, and purge cached artifacts.

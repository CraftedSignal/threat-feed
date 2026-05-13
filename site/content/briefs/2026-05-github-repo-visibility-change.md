---
title: GitHub Private Repository Turned Public
slug: 2026-05-github-repo-visibility-change
description: The rule detects when a private GitHub repository's visibility is changed to public, potentially indicating exfiltration of sensitive code or data and unauthorized access.
date: "2026-05-13T12:20:52Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - github
  - exfiltration
  - cloud
vendors:
  - GitHub
products:
  - github.com
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/exfiltration_github_private_repository_turned_public.toml
  - https://attack.mitre.org/techniques/T1020/
  - https://attack.mitre.org/techniques/T1567/
  - https://attack.mitre.org/techniques/T1567/001/
  - https://attack.mitre.org/tactics/TA0010/
  - https://attack.mitre.org/tactics/TA0040/
rules:
  - title: GitHub Private Repository Turned Public
    description: Detects when a private GitHub repository is changed to public visibility, potentially indicating exfiltration.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1567.001
    data_sources:
      - webserver
  - title: GitHub Repository Visibility Changed to Public via API
    description: Detects when a private GitHub repository is changed to public visibility via API calls.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1567.001
    data_sources:
      - webserver
rules_count: 2
---

This detection rule identifies instances where the visibility of a private GitHub repository is changed to public. This activity can be indicative of malicious exfiltration attempts, where sensitive code, data, or credentials within the repository are exposed. Attackers may compromise user accounts with repository access and then change the repository's visibility to facilitate unauthorized data retrieval. The rule specifically monitors GitHub audit logs for repository visibility modifications. Defenders should investigate any such changes to ensure they are authorized and legitimate, and to verify the integrity of the repository's contents.

## Attack Chain

1. An attacker gains unauthorized access to a GitHub user account with repository administrator privileges.
2. The attacker authenticates to GitHub using the compromised credentials, typically via the web UI or API.
3. The attacker navigates to the settings page of a private repository they have access to.
4. The attacker modifies the repository's visibility settings from "private" to "public".
5. The change is recorded in the GitHub audit logs with the `repo.access` event and `public` visibility status.
6. The attacker forks or mirrors the now-public repository to an external account.
7. The attacker downloads sensitive data, code, or credentials from the exposed repository.
8. The attacker attempts to cover their tracks by deleting logs or making subtle changes to the repository.

## Impact

A successful attack can lead to the exposure of sensitive source code, proprietary algorithms, internal documentation, API keys, and other confidential information stored within the GitHub repository. The severity of the impact depends on the type and sensitivity of data exposed, potentially leading to intellectual property theft, data breaches, financial loss, and reputational damage. Because this is a low severity rule, triage is very important to minimize false positives.

## Recommendation

*   Deploy the Sigma rule `GitHub Private Repository Turned Public` to your SIEM and tune for your environment.
*   Review the GitHub audit logs for `repo.access` events with `public` visibility.
*   Investigate any unauthorized or unexpected changes to repository visibility.
*   Restrict who can change repository visibility to organization owners and enforce SSO and 2FA for maintainers.

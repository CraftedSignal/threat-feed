---
title: GitHub Repository Deletion Detection
slug: 2024-02-github-repo-delete
description: Detection of unauthorized GitHub repository deletion within an organization, potentially leading to irreversible data loss and indicating compromise.
date: "2024-02-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - github
  - repository
  - deletion
  - impact
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/impact_github_repository_deleted.toml
  - https://attack.mitre.org/techniques/T1485/
  - https://attack.mitre.org/tactics/TA0040/
rules:
  - title: GitHub Repository Deleted
    description: Detects when a GitHub repository is deleted within your organization.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: GitHub Audit Log - Repository Deletion
    description: Detects a GitHub repository deletion event based on audit log data.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This detection rule identifies the deletion of GitHub repositories within an organization. GitHub repositories are critical assets for managing code, collaborating, and releasing products. Unauthorized deletion can result in significant intellectual property loss and may signify a security breach. The rule focuses on monitoring GitHub audit logs for repository deletion events to enable prompt investigation of potentially malicious activities. The rule leverages EQL and targets logs ingested into Elasticsearch under the `logs-github.audit-*` index pattern. The rule was last updated on 2026/04/10.

## Attack Chain

1.  An attacker compromises a user account with repository deletion privileges.
2.  The attacker authenticates to GitHub using the compromised credentials.
3.  The attacker navigates to the settings page of the target repository.
4.  The attacker initiates the repository deletion process.
5.  GitHub logs the `repo.destroy` event in the audit logs.
6.  The Elastic detection rule identifies the `repo.destroy` event based on the `event.module` and `data_stream.dataset` fields.
7.  The SOC analyst investigates the alert to determine the legitimacy of the deletion.
8.  If unauthorized, the organization restores the repository from backups and takes steps to remediate the compromised account.

## Impact

The unauthorized deletion of GitHub repositories can have serious consequences, including the loss of critical source code, project data, and intellectual property. This can disrupt ongoing development efforts, delay product releases, and damage an organization's reputation. The number of affected repositories and the sensitivity of the data they contain will determine the overall impact.

## Recommendation

*   Deploy the Sigma rule `GitHub Repository Deleted` to your SIEM to detect unauthorized repository deletions.
*   Review GitHub audit logs for `event.module` is "github", `event.dataset` is "github.audit", and `event.action` is "repo.destroy" to confirm repository deletion events.
*   Implement multi-factor authentication (MFA) for all GitHub accounts, especially those with administrative privileges, to prevent unauthorized access.
*   Enforce role-based access control (RBAC) to limit repository deletion permissions to authorized personnel only.
*   Monitor user activity for suspicious behavior, such as unusual access patterns or attempts to escalate privileges.

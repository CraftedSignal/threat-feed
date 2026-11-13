---
brief_id: brief-2026-11-13-github-repo-exfiltration
event_id: brief-2026-11-13-github-repo-exfiltration
revision: 1
activity_at: "2026-11-13T17:37:10Z"
title: 'GitHub: Repository transfer exfiltration risk'
slug: 2026-11-github-repo-exfiltration
description: GitHub repository transfers can be misused to exfiltrate intellectual property by moving repositories out of an organization's control to an unauthorized account.
date: "2026-11-13T17:37:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - cloud
  - saas
  - github
  - exfiltration
  - collection
vendors:
  - GitHub
products:
  - GitHub
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Adversaries who have compromised a privileged account or token use outgoing transfers to move intellectual property to an account they control, making this both a collection and an exfiltration technique.
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    subtechnique_id: T1213.003
    subtechnique_name: Code Repositories
    evidence: A repository transfer moves the source code, issue history, pull requests, wikis, and settings to another user or organization and removes it from the originating organization's control.
references:
  - https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/exfiltration_github_repository_transferred.toml
rules:
  - title: GitHub Repository Transferred Out of Organization
    description: Identifies when a GitHub repository is transferred out of an organization, which can indicate the exfiltration of intellectual property via an authorized or compromised account.
    platform: sigma
    severity: medium
    data_sources:
      - github.audit
rules_count: 1
---

GitHub repository transfers enable the movement of a repository - including source code, issue history, pull requests, and settings - to another user or organization. While used for legitimate organizational restructuring, this mechanism is also an exfiltration technique. Adversaries who have compromised a privileged account or token can move sensitive repositories to an attacker-controlled account, removing the repository from the source organization's control.

## Impact
An unauthorized repository transfer results in the removal of the repository from the source organization's control, which can permanently exfiltrate intellectual property and bypass standard monitoring controls focused on cloning or archive downloads.

## Recommendation
Detection teams should monitor for the `repo.transfer_outgoing` audit event. During investigation, identify the actor, token, and destination owner to determine if the transfer was approved. Ensure that organizational repository ownership and administrative permissions are properly secured.

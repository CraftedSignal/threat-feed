---
brief_id: brief-2026-11-13-github-ssh-persistence
event_id: brief-2026-11-13-github-ssh-persistence
revision: 1
activity_at: "2026-11-13T15:53:37Z"
title: GitHub account manipulation via SSH key addition
slug: 2026-11-github-ssh-persistence
description: Adversaries may add unauthorized SSH public keys to GitHub user accounts or repositories to maintain persistent, independent access to source code and infrastructure after initial credentials or tokens are invalidated.
date: "2026-11-13T15:53:37Z"
lastmod: "2026-11-13T15:53:56Z"
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
  - persistence
  - cloud
  - github
  - saas
  - collection
  - exfiltration
vendors:
  - GitHub
products:
  - GitHub (Audit Logs)
  - github.com
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    subtechnique_id: T1098.001
    subtechnique_name: Additional Cloud Credentials
    evidence: Identifies the addition of an SSH public key to a GitHub user account or a deploy key to a repository.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    subtechnique_id: T1213.003
    subtechnique_name: Code Repositories
    evidence: Adversaries use it to collect source code without a git clone.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    subtechnique_id: T1567.001
    subtechnique_name: Exfiltration to Code Repository
    evidence: The repo.download_zip action retrieves a full repository archive over HTTP, so adversaries use it to collect source code.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/persistence_github_user_ssh_key_added.toml
  - https://github.blog/news-insights/company-news/security-alert-new-phishing-campaign-targets-github-users/
  - https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account
  - https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/exfiltration_github_high_number_of_zip_downloads.toml
  - https://securitylabs.datadoghq.com/articles/mapping-out-your-unknown-threat-hunters-guide-to-github/
  - https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/
  - https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-zip
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Investigate public_key.create events in GitHub audit logs
      technique_id: T1098.001
      data_needed:
        - github.actor_ip
        - github.user_agent
        - user.name
        - github.repo
        - github.programmatic_access_type
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This rule fires on GitHub's public_key.create audit action, which records the addition of an SSH public key to a user account or a deploy key to a repository.
    - lead: Aggregate 'repo.download_zip' events by user.name and github.actor_ip to identify bulk download activity (8+ events per 10 minutes).
      technique_id: T1567.001
      data_needed:
        - github.audit
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The rule groups downloads by user.name and github.actor_ip in a 10-minute window, requires a high archive-download count.
updates:
  - at: "2026-11-13T15:53:56Z"
    level: L2
    summary: added coverage for github.com
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/exfiltration_github_high_number_of_zip_downloads.toml
---

GitHub audit logs can be used to track the addition of SSH public keys (`public_key.create`), which grant persistent Git access. Attackers leverage this to maintain a foothold in an environment if their initial access method (such as a phished password or compromised personal access token) is remediated. In non-EMU enterprise environments, user-level key creation events may only be recorded in per-user security logs rather than centralized audit streams, creating a visibility gap.

## Impact

Unauthorized access to source code repositories, CI/CD pipelines, and other integrated services, enabling theft of intellectual property or long-term persistence in development workflows.

## Recommendation

Detection teams should monitor GitHub audit logs for `public_key.create` events. High-risk indicators include keys added from unfamiliar IP addresses or via programmatic tokens that indicate account takeover. Ensure that security logs are properly aggregated from both repository and individual user audit streams. Implement policies requiring hardware-backed keys or SSH certificates where possible.

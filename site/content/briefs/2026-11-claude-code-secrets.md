---
brief_id: brief-2026-11-09-claude-code-secrets
event_id: brief-2026-11-09-claude-code-secrets
revision: 1
activity_at: "2026-11-09T17:32:43Z"
title: 'Anthropic Claude Code: Sensitive credential exposure in settings files'
slug: 2026-11-claude-code-secrets
description: Anthropic Claude Code incorrectly persists sensitive command strings containing secrets into local settings files, which are frequently committed to public version control due to configuration oversights.
date: "2026-11-09T17:32:43Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - credential-exposure
  - sensitive-data
  - git
  - cloud
vendors:
  - Anthropic
products:
  - Claude Code
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: The leak stems from the way Claude Code handles user approval for automated shell commands... including any sensitive information that may be embedded within it.
    confidence_band: high
references:
  - https://arstechnica.com/ai/2026/11/claude-code-settings-files-expose-thousands-of-secrets-on-github/
  - https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Scan all enterprise-managed Git repositories for the presence of .claude/settings.local.json files.
      owner: SOC
      due: 24h
      evidence: Researchers identified over 100,000 cases where Claude Code’s local settings file had been uploaded to a public GitHub repository.
  hunt_leads:
    - lead: Identify commits containing .claude/settings.local.json in version control metadata.
      technique_id: T1552.001
      data_needed:
        - Git commit history logs
        - GitHub organization repository search results
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Apiiro’s researchers found over 100,000 cases where Claude Code’s local settings file had been uploaded to a public GitHub repository.
  mitigation_plan:
    - priority: immediate
      action: Rotate all credentials potentially exposed in .claude/settings.local.json files.
      owner: IT Operations
      addresses: Credential compromise
      evidence: found thousands of secrets, including database passwords, API tokens, and root logins
---

Claude Code stores user-approved automated shell commands in a local '.claude/settings.local.json' file when the "Yes, and don't ask again" option is selected. These entries often include raw command strings containing sensitive information such as database passwords, API tokens, and root credentials. While Anthropic documentation suggests this file is included in global '.gitignore' lists, it is frequently absent from repo-level configurations, leading to the accidental exposure of these credentials in public GitHub repositories.

## Impact

Researchers identified over 100,000 instances of this file in public repositories, with at least 1,100 files across 63 organizations confirmed to contain high-value secrets. These secrets remain accessible via project forks even after the primary repository is cleaned.

## Recommendation

- Implement secret scanning (e.g., Gitleaks, TruffleHog) on all internal and public-facing Git repositories, specifically targeting '.claude/settings.local.json' files.
- Audit existing public and internal Git repositories for the presence of the '.claude/' directory.
- Manually configure global '.gitignore' files across all developer workstations to include '.claude/settings.local.json'.
- Revoke and rotate any credentials discovered in exposed '.claude/' settings files.

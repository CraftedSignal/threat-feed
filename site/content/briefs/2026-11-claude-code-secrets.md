---
brief_id: brief-2026-11-09-claude-code-secrets
event_id: brief-2026-11-09-claude-code-secrets
revision: 2
activity_at: "2026-11-09T18:36:18Z"
revision_history:
  - revision: 2
    at: "2026-11-09T18:36:18Z"
    checksum: sha256:c69246e1a51a185124b8cea4e4758db0504fbb44b40c692a09671edefbfe0d30
    summary: added coverage for Claude Code +1 products
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://www.darkreading.com/endpoint-security/attackers-claude-office-party-flaw-malicious-code-linux
title: 'Anthropic Claude Code: Sensitive credential exposure in settings files'
slug: 2026-11-claude-code-secrets
description: Anthropic Claude Code incorrectly persists sensitive command strings containing secrets into local settings files, which are frequently committed to public version control due to configuration oversights.
date: "2026-11-09T17:32:43Z"
lastmod: "2026-11-09T18:35:43Z"
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
  - application-security
  - arbitrary-code-execution
  - linux
  - ai-security
vendors:
  - Anthropic
products:
  - Claude Code
  - LibreOffice
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: The leak stems from the way Claude Code handles user approval for automated shell commands... including any sensitive information that may be embedded within it.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574.006
    technique_name: Dynamic Linker Hijacking
    evidence: When the script encounters an environment where Unix-domain sockets cannot be opened, it uses a workaround that loads a shared library through the Linux LD_PRELOAD mechanism.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574.006
    technique_name: Dynamic Linker Hijacking
    evidence: An attacker who can place a malicious library at that location... can potentially have their code loaded and executed... with the privileges of the user running the AI agent.
    confidence_band: high
references:
  - https://arstechnica.com/ai/2026/11/claude-code-settings-files-expose-thousands-of-secrets-on-github/
  - https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again
  - https://www.darkreading.com/endpoint-security/attackers-claude-office-party-flaw-malicious-code-linux
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
    - action: Perform an inventory of all active AI skills and add-ons running in Linux-based developer environments.
      owner: SOC
      due: 48h
      evidence: Companies don’t have visibility to which skills and other agent add-ons they have installed.
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
    - lead: Identify file writes to system temporary directories (e.g., /tmp, /var/tmp) involving .so files created by processes associated with AI agent document processing.
      technique_id: T1574.006
      data_needed:
        - Auditd file_event or EDR process_creation/file_write telemetry
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An attacker gets one malicious file into a shared temporary folder which many programs use.
  mitigation_plan:
    - priority: immediate
      action: Rotate all credentials potentially exposed in .claude/settings.local.json files.
      owner: IT Operations
      addresses: Credential compromise
      evidence: found thousands of secrets, including database passwords, API tokens, and root logins
    - priority: medium
      action: Apply strict file system permissions on temporary directories used by AI agent helper scripts to limit write access.
      owner: IT Operations
      addresses: Office Party vulnerability
      evidence: An attacker who can place a malicious library at that location... can potentially have their code loaded.
updates:
  - at: "2026-11-09T18:35:43Z"
    level: L1
    summary: added coverage for Claude Code +1 products
    sources:
      - dark-reading
    source_urls:
      - https://www.darkreading.com/endpoint-security/attackers-claude-office-party-flaw-malicious-code-linux
---

Claude Code stores user-approved automated shell commands in a local '.claude/settings.local.json' file when the "Yes, and don't ask again" option is selected. These entries often include raw command strings containing sensitive information such as database passwords, API tokens, and root credentials. While Anthropic documentation suggests this file is included in global '.gitignore' lists, it is frequently absent from repo-level configurations, leading to the accidental exposure of these credentials in public GitHub repositories.

## Impact

Researchers identified over 100,000 instances of this file in public repositories, with at least 1,100 files across 63 organizations confirmed to contain high-value secrets. These secrets remain accessible via project forks even after the primary repository is cleaned.

## Recommendation

- Implement secret scanning (e.g., Gitleaks, TruffleHog) on all internal and public-facing Git repositories, specifically targeting '.claude/settings.local.json' files.
- Audit existing public and internal Git repositories for the presence of the '.claude/' directory.
- Manually configure global '.gitignore' files across all developer workstations to include '.claude/settings.local.json'.
- Revoke and rotate any credentials discovered in exposed '.claude/' settings files.

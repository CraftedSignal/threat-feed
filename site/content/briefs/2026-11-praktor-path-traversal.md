---
brief_id: brief-2026-11-04-praktor-path-traversal
event_id: brief-2026-11-04-praktor-path-traversal
revision: 1
activity_at: "2026-11-04T04:13:34Z"
title: 'praktor: Path traversal and stored instruction injection (CVE-2026-62331)'
slug: 2026-11-praktor-path-traversal
description: The praktor agent platform allows unauthenticated Telegram users to perform path traversal and stored instruction injection by uploading files with malicious filenames, enabling arbitrary file write access to the agent workspace.
date: "2026-11-04T04:13:34Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified information only.
cpes:
  - cpe:2.3:a:mtzanidakis:praktor:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - instruction-injection
  - agent-security
  - vulnerability
vendors:
  - mtzanidakis
products:
  - praktor (<= 0.9.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'By default the bot has no user allowlist (allow_from: [] means "allow all"), so the only precondition is that a user can message the bot.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Inter-Process Communication
    evidence: This turns a file upload into a stored injection into the agent's instruction/execution surface.
    confidence_band: high
cves:
  - id: CVE-2026-62331
    cvss: 8.2
    epss: 0.00778
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-48v2-6jcm-fc99
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62331
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade praktor to version 0.9.1 or later
      owner: IT Operations
      due: 24h
      evidence: 'Patched versions v0.9.1, containing PR #228.'
  hunt_leads:
    - lead: Hunt for file writes in the persistent workspace directory that originated from the Telegram bot process
      technique_id: T1565.001
      data_needed:
        - Application audit logs or container file integrity logs for /workspace/agent
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An attacker can use .. sequences to write files outside the designated uploads/ directory into the persistent agent workspace volume.
  mitigation_plan:
    - priority: immediate
      action: Restrict telegram.allow_from to trusted user IDs
      owner: IT Operations
      addresses: CVE-2026-62331
      evidence: Restrict telegram.allow_from to trusted user IDs to limit who can send uploads to the bot.
---

The praktor agent platform is susceptible to a path traversal vulnerability (CVE-2026-62331) in its Telegram bot implementation. An attacker can supply a specially crafted filename containing directory traversal sequences (e.g., '../') during a file upload via Telegram. Because the platform fails to sanitize these filenames before writing them to the persistent agent workspace volume, an attacker can write files outside the intended 'uploads/' directory. This allows for the overwriting or creation of critical agent files, such as instructions, hooks, or configuration files, leading to stored instruction injection within the AI agent's environment.

## Impact
Successful exploitation allows a remote, unauthenticated Telegram user to write arbitrary files to the agent's persistent workspace volume. This can lead to the manipulation of agent behavior, configuration, or logic, as the AI agent consumes these files during subsequent execution runs.

## Recommendation
- Upgrade the praktor installation to version 0.9.1 or later to incorporate the fix implemented in PR #228.
- Implement access control by restricting the `telegram.allow_from` configuration setting to trusted Telegram user IDs.
- Audit the `/workspace/agent` directory for unexpected files or modifications if the instance was potentially exposed to unauthorized Telegram users.

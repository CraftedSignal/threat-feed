---
title: Detection of Potential Credential Discovery via Recursive Grep
slug: 2026-09-recursive-grep-credential-discovery
description: This threat brief details the identification of recursive grep activity on Linux and macOS used by adversaries or insiders to discover credentials, keys, and tokens within the filesystem.
date: "2026-09-18T19:08:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - discovery
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Adversaries and insider threats sometimes use grep -r ... to find passwords, API keys, private keys, cloud tokens.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Adversaries and insider threats sometimes use grep -r ... across directories to find passwords.
    confidence_band: high
rules:
  - title: Potential Credential Discovery via Recursive Grep
    description: Detects recursive grep activity on Linux or macOS suggesting the search for secrets, credentials, or sensitive paths (e.g., .env, .git, .aws).
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1083
      - T1552.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to detect recursive grep secret hunting.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for high-frequency recursive grep executions in historical logs.
      technique_id: T1552.001
      priority: medium
      confidence: medium
      disposition: hunt_now
  mitigation_plan:
    - priority: short_term
      action: Enforce principle of least privilege on sensitive configuration files and directories.
      owner: IT Operations
---

Adversaries and insider threats often perform reconnaissance on compromised hosts to identify secrets, API keys, private keys, cloud tokens, or configuration files containing sensitive credentials. A common, low-effort technique involves using recursive search utilities, specifically `grep` or `egrep` with the `-r` or `--recursive` flags, to scan directory structures for patterns indicative of secrets (e.g., `.env`, `.aws`, `.git`, `xoxb-`, or `ghp_`). 

This activity is inherently suspicious when observed at scale, as it indicates a broad search rather than targeted developer access. Detection requires aggregating distinct command executions to filter out noise from automated security scanners, CI/CD pipelines, or legitimate administrative audits. Defenders should focus on high-frequency, unique recursive searches initiated by interactive shell processes or unexpected scripts.

## Attack Chain

1. Initial access is established on a Linux or macOS system via SSH, web shell, or malicious payload execution.
2. The actor identifies the need to escalate privileges or move laterally by harvesting credentials stored on the local disk.
3. The actor executes a recursive grep command (e.g., `grep -r "API_KEY" /home/user/`) to identify potential secret files.
4. The actor broadens the search to include sensitive path prefixes such as `/.env` or `/.aws/`.
5. Multiple unique grep queries are executed in rapid succession to bypass simple file-level monitoring.
6. Discovered credentials (SSH keys, cloud tokens) are exfiltrated to adversary-controlled C2 infrastructure.

## Impact

Successful execution of this discovery technique allows attackers to obtain hardcoded credentials, cloud environment tokens, and configuration secrets. This frequently leads to unauthorized access to cloud services (AWS, Slack, Discord, GitHub), lateral movement through SSH key theft, or complete environment compromise, potentially impacting software supply chains if CI/CD secrets are exposed.

## Recommendation

- Implement the provided Sigma rule to detect recursive grep patterns associated with secret discovery.
- Tune the detection logic by excluding known-good automated processes (e.g., CI/CD agents, security scanners) to reduce false positives.
- Investigate alerts by reviewing `process.parent.command_line` to confirm the context of the discovery attempt.
- Rotate any credentials identified as potentially exposed in directories targeted by anomalous grep activity.

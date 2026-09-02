---
title: Arbitrary Code Execution in AI Coding Agents via Git Configuration
slug: 2026-09-gitspawn-ai-agent-rce
description: Multiple AI coding agents are vulnerable to arbitrary code execution due to the automated, unsandboxed execution of commands defined within a repository's local Git configuration, specifically the 'core.fsmonitor' setting.
date: "2026-09-02T14:20:59Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - supply-chain
  - rce
  - ai-security
  - git
vendors:
  - OpenAI
  - Anthropic
  - Nous Research
  - Alibaba
  - xAI
  - Cursor
products:
  - goose (< 1.44.0)
  - Codex CLI (0.102.0 - 0.130.0)
  - Codex Desktop for macOS (260202.0859 - 26.513.31313)
  - Codex Desktop for Windows (26.304.38 - 26.513.40821)
  - Claude Code (2.1.193, 2.1.252)
  - Hermes Agent (0.18.2, 0.21.0)
  - Qwen Code (0.19.6, 0.22.3)
  - Grok Build (0.2.93, 1.0.13)
  - Cursor CLI
affected_os:
  - Windows
  - macOS
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The command executes as the user, outside the agent's sandbox and without an approval prompt.
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/malicious-git-configs-can-make-claude.html
rules:
  - title: Detect Git Subprocess Execution by AI Agents
    description: Detects AI coding agents spawning git processes with potentially risky configuration flags or operating on directories that could contain malicious configs
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch all AI coding agents to latest available versions provided by vendors.
      owner: IT Operations
      due: 48h
      evidence: Source provides list of patched versions for goose, Codex, etc.
    - action: Enforce global git config setting to disable core.fsmonitor on all workstations.
      owner: IT Operations
      due: 24h
      evidence: 'Source recommendation: ''Set git config --global core.fsmonitor false'''
  hunt_leads:
    - lead: Search endpoint logs for git processes spawned by AI agent binaries.
      technique_id: T1059.003
      data_needed:
        - Sysmon EID 1 (Process Creation)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Manifold Security report on GitSpawn behavior.
  mitigation_plan:
    - priority: immediate
      action: Upgrade goose to 1.44.0, Codex CLI to 0.131.0, and other agents to fixed versions.
      owner: IT Operations
      addresses: Known vulnerable AI agents
      evidence: Source lists fixed version numbers.
---

Manifold Security has disclosed eight security vulnerabilities affecting seven command-line AI coding agents, collectively dubbed GitSpawn. The flaw stems from the agents' behavior of reading and executing commands defined in a repository's local Git configuration file ('.git/config') during routine repository indexing operations like 'git status' or 'git diff'. Specifically, the 'core.fsmonitor' Git configuration parameter, which is intended to identify changed files, can be abused by an attacker to specify an arbitrary command that the host agent executes. This command runs with the privileges of the developer, bypasses the agent's sandbox, and executes before any user-approval or workspace-trust prompt. Impacted agents include goose, Claude Code, Cursor, Codex, Hermes Agent, Qwen Code, and Grok Build. While some vendors have released patches, others remain vulnerable. Exploitation requires the victim to open a malicious repository containing a manipulated '.git' directory, typically provided via shared archives, sync folders, or removable media.

## Attack Chain

1. Attacker creates a malicious Git repository containing a crafted '.git/config' file.
2. The '.git/config' file is modified to set 'core.fsmonitor' to an arbitrary malicious command or script path.
3. The repository is delivered to a developer via a shared folder, USB drive, or archive that preserves the hidden '.git' directory.
4. The developer opens the repository directory using an affected AI coding agent.
5. The AI agent initiates a background Git operation (such as 'git status' or 'git diff') to index the workspace.
6. Git reads the malicious 'core.fsmonitor' configuration and automatically executes the defined command.
7. The command executes on the developer's machine with user-level privileges, outside the agent's sandbox.
8. Final objective is achieved, such as file exfiltration, unauthorized file modification, or further payload delivery.

## Impact

The vulnerability allows unauthenticated attackers to achieve full code execution on developer machines, potentially leading to the theft of source code, credentials, or other sensitive files accessible to the user. While no widespread in-the-wild exploitation has been confirmed as of September 2026, the potential for supply chain attacks against software development organizations is significant. Multiple agents remain unpatched as of the disclosure, and the issue affects major platforms including Windows, macOS, and Linux.

## Recommendation

- Immediately audit development environments for the listed vulnerable AI coding agent versions and apply patches where available (e.g., upgrade goose to 1.44.0+).
- Globally disable the 'core.fsmonitor' feature in Git configuration for untrusted repositories by running 'git config --global core.fsmonitor false'.
- Inspect '.git/config' files for suspicious 'core.fsmonitor', 'core.hooksPath', or 'attr.tree' entries before opening repositories with AI-integrated tools.
- Deploy detection rules to identify execution of Git sub-processes initiated by AI agent binaries that contain suspicious command-line arguments.

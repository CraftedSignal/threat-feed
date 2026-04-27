---
title: Claude Code Trust Dialog Bypass via Git Worktree Spoofing
slug: 2026-04-claude-code-trust-bypass
description: A vulnerability in Claude Code allowed for trust dialog bypass via git worktree spoofing, potentially leading to arbitrary code execution by crafting a malicious repository with a `commondir` file pointing to a previously trusted path, bypassing the trust dialog, and executing malicious hooks defined in `.claude/settings.json`.
date: "2026-04-25T12:00:00Z"
severities:
  - high
tags:
  - git
  - code-execution
  - trust-bypass
vendors:
  - Anthropic
products:
  - Claude Code
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://github.com/advisories/GHSA-q5hj-mxqh-vv77
rules:
  - title: Detect Suspicious .claude/settings.json Modification
    description: Detects modification of .claude/settings.json with potentially malicious content, indicating a possible trust bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Process Launched from Claude Code Context
    description: Detects processes launched from Claude Code that are not expected, potentially indicating code execution from a malicious settings file.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A vulnerability in Claude Code, specifically versions 2.1.63 and later but before 2.1.84, allowed for a trust dialog bypass via Git worktree spoofing. This exploit leverages the way Claude Code determines folder trust using the `commondir` file in Git worktrees. By crafting a repository containing a `commondir` file that points to a path the victim has previously trusted, an attacker could bypass the trust dialog, leading to arbitrary code execution through malicious hooks defined in the…

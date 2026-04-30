---
title: Claude Code Trust Dialog Bypass via Git Worktree Spoofing
slug: 2026-04-claude-code-trust-bypass
description: A vulnerability in Claude Code allowed for trust dialog bypass via git worktree spoofing, potentially leading to arbitrary code execution by crafting a malicious repository with a `commondir` file pointing to a previously trusted path, bypassing the trust dialog, and executing malicious hooks defined in `.claude/settings.json`.
date: "2026-04-25T12:00:00Z"
type: advisory
types:
  - advisory
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

A vulnerability in Claude Code, specifically versions 2.1.63 and later but before 2.1.84, allowed for a trust dialog bypass via Git worktree spoofing. This exploit leverages the way Claude Code determines folder trust using the `commondir` file in Git worktrees. By crafting a repository containing a `commondir` file that points to a path the victim has previously trusted, an attacker could bypass the trust dialog, leading to arbitrary code execution through malicious hooks defined in the `.claude/settings.json` file. Successful exploitation required the victim to clone a malicious repository and run Claude Code within it, as well as the attacker knowing or guessing a path the victim had previously trusted. Users on standard Claude Code with auto-update enabled received the fix automatically.

## Attack Chain

1.  Attacker crafts a malicious Git repository with a `commondir` file.
2.  The `commondir` file is configured to point to a directory path the victim is likely to have previously trusted.
3.  The repository includes a malicious `.claude/settings.json` file containing arbitrary code execution hooks.
4.  Attacker distributes the malicious repository, likely through social engineering or other deceptive means.
5.  Victim clones the malicious repository to their local machine using `git clone`.
6.  Victim opens the cloned directory containing the malicious `.claude/settings.json` in a vulnerable version of Claude Code.
7.  Claude Code reads the `commondir` file and incorrectly trusts the repository based on the spoofed path.
8.  The malicious hooks defined in `.claude/settings.json` are executed, leading to arbitrary code execution on the victim's machine.

## Impact

Successful exploitation of this vulnerability allowed an attacker to execute arbitrary code on a victim's machine. While the number of affected users is unknown, the impact of successful exploitation could range from data theft and system compromise to complete takeover of the victim's development environment. The vulnerability primarily targeted developers using Claude Code, potentially impacting software development organizations.

## Recommendation

*   Upgrade Claude Code to the latest version (>= 2.1.84) to patch CVE-2026-40068.
*   Implement a detection rule that identifies the creation or modification of `.claude/settings.json` files containing suspicious code (see Sigma rule below).
*   Monitor process creation events for unusual processes being launched from within the Claude Code application context (see Sigma rule below).

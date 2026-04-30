---
title: Claude Code Workspace Trust Dialog Bypass via Settings Loading Order (CVE-2026-33068)
slug: 2026-03-claude-code-bypass
description: A maliciously crafted `.claude/settings.json` file in a Claude Code repository (versions prior to 2.1.53) can bypass the workspace trust confirmation dialog by exploiting a configuration loading order defect, allowing for arbitrary code execution within a supposedly untrusted workspace.
date: "2026-03-21T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - claude-code
  - workspace-trust
  - cve-2026-33068
  - bypass
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
references:
  - https://www.reddit.com/r/netsec/comments/1rz2xuw/claude_code_workspace_trust_dialog_bypass_via/
  - https://raxe.ai/labs/advisories/RAXE-2026-040
rules:
  - title: Detect Claude Code Settings File Creation
    description: Detects the creation of a .claude/settings.json file, which could be an indicator of malicious activity related to CVE-2026-33068.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - file_event
      - windows|linux|macos
  - title: Detect Claude Code Executing with Bypassed Permissions
    description: Detects potential exploitation by monitoring for claude-code process execution where permissions appear to be bypassed, based on command line flags.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    data_sources:
      - process_creation
      - windows|linux|macos
rules_count: 2
---

CVE-2026-33068 affects Anthropic's Claude Code CLI tool in versions prior to 2.1.53. The vulnerability stems from a configuration loading order defect where repository-level settings, specifically those defined in `.claude/settings.json`, are resolved before the workspace trust dialog is presented to the user. This allows a malicious repository to include a `.claude/settings.json` file containing `bypassPermissions` entries. These permissions are then applied before the user has the opportunity…

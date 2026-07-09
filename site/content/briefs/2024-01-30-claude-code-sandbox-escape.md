---
title: Claude Code Sandbox Escape via Symlink Following
slug: 2024-01-30-claude-code-sandbox-escape
description: A sandbox escape vulnerability in Claude Code allowed writing arbitrary files outside the workspace by creating symlinks from within the sandbox that were followed by unsandboxed processes, potentially leading to code execution outside the sandbox.
date: "2024-01-30T12:00:00Z"
lastmod: "2026-07-09T05:36:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:anthropic:claude_code:*:*:*:*:*:node.js:*:*
has_poc: true
tags:
  - sandbox-escape
  - symlink
  - arbitrary-file-write
vendors:
  - Anthropic
  - OpenAI
products:
  - Claude Code (CLI 2.1.116)
  - Claude Code (CLI 2.1.196)
  - Claude Code (CLI 2.1.198)
  - Claude Code (CLI 2.1.199)
  - Claude Sonnet 4.6
  - Claude Sonnet 5
  - Claude Opus 4.8
  - OpenAI Codex (CLI 0.142.4)
  - GPT-5.5
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: 'Indicator Removal on Host: Clear Command History'
cves:
  - id: CVE-2026-39861
    cvss: 10
    epss: 0.00518
references:
  - https://github.com/advisories/GHSA-vp62-r36r-9xqp
  - https://thehackernews.com/2026/07/friendly-fire-ai-agents-built-to-catch.html
rules:
  - title: Detect Suspicious Symlink Creation within Claude Code Sandboxes
    description: Detects the creation of symlinks by processes running within the Claude Code sandbox, which could be indicative of a sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - linux
  - title: Detect File Writes Outside Claude Code Workspace via Symlink
    description: Detects file writes to locations outside the expected Claude Code workspace by processes associated with Claude Code, potentially indicating a sandbox escape.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
updates:
  - at: "2026-07-09T05:36:42Z"
    level: L2
    summary: poc_available; added CVE-2026-39861
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/friendly-fire-ai-agents-built-to-catch.html
---

Claude Code versions prior to 2.1.64 contained a sandbox escape vulnerability where sandboxed processes could create symlinks pointing outside the defined workspace. Subsequently, when Claude Code's unsandboxed process wrote to a path within such a symlink, it would follow the symlink and write to the target location outside the workspace. This occurred without user confirmation, circumventing the intended sandbox restrictions. The vulnerability requires an attacker to inject untrusted content into a Claude Code context window, triggering sandboxed code execution through prompt injection. This allows a malicious actor to gain arbitrary file write access and potentially execute code outside the confines of the sandbox, bypassing security controls and potentially compromising the system. The affected package is npm/@anthropic-ai/claude-code, specifically versions less than 2.1.64.

## Attack Chain

1. An attacker crafts a malicious prompt designed to inject code into a Claude Code context window.
2. The injected code is executed within the Claude Code sandbox.
3. The sandboxed process creates a symbolic link (symlink) using standard OS tools (e.g., `ln -s`) pointing from a location within the sandbox to a target location outside the sandbox, such as `/etc/passwd` or a user's `.bashrc`.
4. The unsandboxed Claude Code process attempts to write to a file path that includes the previously created symlink.
5. The unsandboxed process follows the symlink to the external target location.
6. The unsandboxed process writes arbitrary data to the target location outside the sandbox, bypassing intended security restrictions.
7. If a configuration file like `.bashrc` is overwritten, the attacker could achieve code execution upon the next shell startup.
8. Successful exploitation allows the attacker to potentially execute arbitrary code outside the sandbox, compromising the entire system.

## Impact

Successful exploitation of this vulnerability could lead to arbitrary file write access outside the Claude Code sandbox. This allows an attacker to modify critical system files, inject malicious code into startup scripts, or compromise user accounts. While the specific number of victims is not stated, any user running a vulnerable version of Claude Code is susceptible. Sectors at risk include any that rely on the security of the Claude Code sandbox for protecting sensitive data or preventing unauthorized code execution. A successful attack could lead to full system compromise.

## Recommendation

*   Update the npm/@anthropic-ai/claude-code package to version 2.1.64 or later to remediate the vulnerability (reference: Affected Packages).
*   Deploy the Sigma rule "Detect Suspicious Symlink Creation within Claude Code Sandboxes" to identify attempts to create symlinks within the sandbox environment (reference: Sigma Rule).
*   Monitor file system events for writes to unexpected locations from Claude Code processes, paying special attention to writes following symlink traversal (reference: Sigma Rule).

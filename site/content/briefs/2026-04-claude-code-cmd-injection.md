---
title: Anthropic Claude Code CLI/Agent SDK OS Command Injection Vulnerability (CVE-2026-35021)
slug: 2026-04-claude-code-cmd-injection
description: The Anthropic Claude Code CLI and Claude Agent SDK are vulnerable to OS command injection via crafted file paths, allowing arbitrary command execution.
date: "2026-04-06T20:16:25Z"
severities:
  - high
tags:
  - cve-2026-35021
  - command-injection
  - anthropic
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35021
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35021
rules:
  - title: Detect Suspicious Claude CLI/Agent SDK Command Execution
    description: Detects command execution originating from the Claude CLI/Agent SDK with suspicious command line arguments indicative of command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Process Creation with Shell Metacharacters
    description: Detects process creation events with command lines containing shell metacharacters.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The Anthropic Claude Code CLI and Claude Agent SDK are susceptible to an OS command injection vulnerability, as detailed in CVE-2026-35021. This flaw stems from the insufficient sanitization of file paths within the prompt editor invocation utility. An attacker can exploit this vulnerability by injecting shell metacharacters into file paths, which are then interpolated into shell commands executed using `execSync`. The use of double quotes around the file path does not prevent command…

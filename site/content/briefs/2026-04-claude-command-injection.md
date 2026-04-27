---
title: Anthropic Claude Code CLI/SDK OS Command Injection Vulnerability
slug: 2026-04-claude-command-injection
description: CVE-2026-35022 describes an OS command injection vulnerability in the Anthropic Claude Code CLI and Claude Agent SDK that allows attackers with control over authentication settings to execute arbitrary commands, potentially leading to credential theft and environment variable exfiltration.
date: "2026-04-06T20:16:25Z"
severities:
  - critical
tags:
  - command-injection
  - cve-2026-35022
  - anthropic
  - claude
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-35022
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35022
rules:
  - title: Detect Claude CLI/SDK Command Injection via Shell Metacharacters
    description: Detects command injection attempts in the Anthropic Claude CLI or SDK by identifying shell metacharacters in process command lines originating from the CLI or SDK.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Claude CLI/SDK Configuration File Modification
    description: Detects modifications to configuration files associated with the Anthropic Claude CLI or SDK.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Anthropic Claude Code CLI and Claude Agent SDK are vulnerable to OS command injection (CVE-2026-35022). This vulnerability stems from the insecure execution of authentication helper configuration values. Specifically, the application executes commands using `shell=true` without proper input validation on parameters such as `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, and `gcpAuthRefresh`. An attacker who can manipulate these authentication settings can inject shell…

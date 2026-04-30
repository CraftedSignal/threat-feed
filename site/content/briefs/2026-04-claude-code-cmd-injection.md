---
title: Anthropic Claude Code CLI/Agent SDK OS Command Injection Vulnerability (CVE-2026-35021)
slug: 2026-04-claude-code-cmd-injection
description: The Anthropic Claude Code CLI and Claude Agent SDK are vulnerable to OS command injection via crafted file paths, allowing arbitrary command execution.
date: "2026-04-06T20:16:25Z"
severities:
  - high
type: advisory
types:
  - advisory
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

The Anthropic Claude Code CLI and Claude Agent SDK are susceptible to an OS command injection vulnerability, as detailed in CVE-2026-35021. This flaw stems from the insufficient sanitization of file paths within the prompt editor invocation utility. An attacker can exploit this vulnerability by injecting shell metacharacters into file paths, which are then interpolated into shell commands executed using `execSync`. The use of double quotes around the file path does not prevent command substitution, enabling attackers to execute arbitrary commands with the privileges of the user running the CLI, creating a high-risk scenario for compromised systems.

## Attack Chain

1.  Attacker crafts a malicious file path containing shell metacharacters (e.g., `$()`, backticks).
2.  The malicious file path is provided as input to the Anthropic Claude Code CLI or Agent SDK, specifically targeting the prompt editor invocation utility.
3.  The application interpolates the attacker-controlled file path into a shell command.
4.  The shell command, now containing the injected payload, is executed via the `execSync` function.
5.  The shell interprets the injected metacharacters, triggering command substitution.
6.  The attacker's injected commands are executed with the privileges of the user running the CLI or SDK.
7.  The attacker gains arbitrary code execution on the system.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary commands on the affected system. This could lead to complete system compromise, data exfiltration, or deployment of malicious payloads such as ransomware. Due to the nature of the vulnerability, any system utilizing the Claude Code CLI or Agent SDK is potentially at risk if it processes untrusted file paths.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious Claude CLI/Agent SDK Command Execution` to identify potential command injection attempts via process creation logs.
*   Monitor process creation events for command line arguments containing shell metacharacters being passed to processes spawned by the Claude CLI or Agent SDK using the `Process Creation with Shell Metacharacters` Sigma rule.
*   Apply any available patches or updates released by Anthropic to address CVE-2026-35021 once they are available.

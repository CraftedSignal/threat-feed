---
title: Flowise Authenticated Remote Code Execution via MCP Adapter
slug: 2026-04-flowise-rce
description: Flowise versions 3.0.13 and earlier are vulnerable to authenticated arbitrary command execution due to unsafe serialization of stdio commands in the MCP adapter, allowing a malicious user to execute commands on the underlying operating system.
date: "2026-04-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - flowise
  - rce
  - command-injection
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-c9gw-hvqq-f33r
rules:
  - title: Detect Flowise MCP Command Execution
    description: Detects command execution via Flowise MCP adapter vulnerability by monitoring for 'npx -c' execution where the parent process is related to Flowise.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Flowise MCP Command Execution (Windows)
    description: Detects command execution via Flowise MCP adapter vulnerability by monitoring for 'npx -c' execution where the parent process is related to Flowise on Windows.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Flowise MCP Command Injection via touch
    description: Detects command injection via Flowise MCP adapter vulnerability by monitoring for 'touch /tmp/pwn' execution where the parent process is related to Flowise.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Flowise is an open-source low-code platform to build customized AI flow. Versions 3.0.13 and earlier contain a critical vulnerability that allows authenticated users to execute arbitrary commands on the underlying operating system. This vulnerability stems from insufficient input sanitization within the MCP (Model Composition Protocol) adapter. By adding a new MCP using stdio, an attacker can inject malicious commands, bypassing existing sanitization checks. Specifically, the vulnerability lies in the "Custom MCP" configuration where commands like "npx" can be combined with code execution arguments (e.g., "npx -c touch /tmp/pwn"), leading to direct code execution. This vulnerability affects both the `flowise` and `flowise-components` packages.

## Attack Chain

1.  Attacker authenticates to the Flowise application.
2.  Attacker navigates to the Custom MCP configuration page (e.g., `/canvas`).
3.  Attacker creates a new Custom MCP adapter.
4.  Attacker configures the MCP adapter to use stdio.
5.  Attacker injects a malicious command, such as "npx -c touch /tmp/pwn", into the command or arguments fields. This bypasses `validateCommandInjection` and `validateArgsForLocalFileAccess` checks.
6.  Flowise application executes the attacker-supplied command via the MCP adapter.
7.  Malicious command is executed on the underlying operating system.
8.  Attacker achieves arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to achieve arbitrary command execution on the Flowise server. This could lead to complete system compromise, data theft, or denial of service. The vulnerability affects Flowise installations running versions 3.0.13 and earlier. The number of affected installations is currently unknown, but given the popularity of Flowise, the potential impact is significant.

## Recommendation

*   Upgrade Flowise and Flowise-components to a version greater than 3.0.13 to patch CVE-2026-40933.
*   Monitor process creation events for the execution of "npx" with the "-c" argument where the parent process is the Flowise application. Deploy the provided Sigma rule `Detect Flowise MCP Command Execution` to identify potential exploitation attempts.
*   Implement stricter input validation and sanitization measures within the MCP adapter configuration to prevent command injection attacks.

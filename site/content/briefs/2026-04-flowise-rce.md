---
title: Flowise Authenticated Remote Code Execution via MCP Adapter
slug: 2026-04-flowise-rce
description: Flowise versions 3.0.13 and earlier are vulnerable to authenticated arbitrary command execution due to unsafe serialization of stdio commands in the MCP adapter, allowing a malicious user to execute commands on the underlying operating system.
date: "2026-04-17T12:00:00Z"
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

Flowise is an open-source low-code platform to build customized AI flow. Versions 3.0.13 and earlier contain a critical vulnerability that allows authenticated users to execute arbitrary commands on the underlying operating system. This vulnerability stems from insufficient input sanitization within the MCP (Model Composition Protocol) adapter. By adding a new MCP using stdio, an attacker can inject malicious commands, bypassing existing sanitization checks. Specifically, the vulnerability lies…

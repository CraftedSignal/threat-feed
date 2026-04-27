---
title: '@mobilenext/mobile-mcp Path Traversal Vulnerability'
slug: 2024-01-04-mobile-mcp-path-traversal
description: The @mobilenext/mobile-mcp package before version 0.0.49 is vulnerable to a Path Traversal vulnerability in the mobile_save_screenshot and mobile_start_screen_recording tools where the `saveTo` and `output` parameters are passed directly to filesystem operations without validation, potentially allowing an attacker to write files outside the intended workspace, leading to privilege escalation and persistence by overwriting sensitive host files.
date: "2026-03-27T19:13:17Z"
severities:
  - high
tags:
  - path-traversal
  - file-write
  - privilege-escalation
  - persistence
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://github.com/advisories/GHSA-3p2m-h2v6-g9mx
rules:
  - title: Detect Mobile-MCP Path Traversal Attempts
    description: Detects attempts to exploit the path traversal vulnerability in @mobilenext/mobile-mcp by monitoring for calls to 'mobile_save_screenshot' or 'mobile_start_screen_recording' with suspicious file paths.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: Detect Mobile-MCP Arbitrary File Write via API Call
    description: Detects attempts to write arbitrary files by monitoring API calls with base64 encoded command lines or shell commands.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `@mobilenext/mobile-mcp` npm package, versions prior to 0.0.49, contains a critical path traversal vulnerability. This flaw stems from the `mobile_save_screenshot` and `mobile_start_screen_recording` tools which improperly handle user-supplied paths. Specifically, the `saveTo` parameter in `mobile_save_screenshot` and the `output` parameter in `mobile_start_screen_recording` are passed directly to filesystem write operations without adequate validation. This oversight enables a malicious…

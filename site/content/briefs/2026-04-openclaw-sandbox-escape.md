---
title: OpenClaw TOCTOU Race Condition Leads to Sandbox Escape
slug: 2026-04-openclaw-sandbox-escape
description: A critical time-of-check time-of-use (TOCTOU) vulnerability in OpenClaw's remote file system bridge allows a sandbox escape by exploiting the delay between path validation and file reading, affecting versions up to 2026.3.28.
date: "2026-04-03T03:15:00Z"
severities:
  - critical
tags:
  - openclaw
  - sandbox-escape
  - toctou
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-9p3r-hh9g-5cmg
rules:
  - title: Detect OpenClaw Suspicious File Access Outside Expected Path
    description: Detects potential TOCTOU exploitation attempts in OpenClaw by monitoring for file reads immediately after path validation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect OpenClaw File Path Manipulation via Symlink
    description: Detects potential TOCTOU exploitation via symlink manipulation by monitoring symlink creation followed by file access by OpenClaw.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw versions up to and including 2026.3.28 contain a critical vulnerability related to how they handle remote file system operations within a sandboxed environment. Specifically, the `readFile` function in the remote file system bridge is susceptible to a Time-of-Check Time-of-Use (TOCTOU) race condition. This means that the application verifies the path of a file before reading it, but an attacker can potentially modify the file path in between the check and the read operation. The…

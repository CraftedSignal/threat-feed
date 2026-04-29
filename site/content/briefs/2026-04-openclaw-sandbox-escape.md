---
title: OpenClaw TOCTOU Race Condition Leads to Sandbox Escape
slug: 2026-04-openclaw-sandbox-escape
description: A critical time-of-check time-of-use (TOCTOU) vulnerability in OpenClaw's remote file system bridge allows a sandbox escape by exploiting the delay between path validation and file reading, affecting versions up to 2026.3.28.
date: "2026-04-03T03:15:00Z"
type: coverage
types:
  - coverage
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

OpenClaw versions up to and including 2026.3.28 contain a critical vulnerability related to how they handle remote file system operations within a sandboxed environment. Specifically, the `readFile` function in the remote file system bridge is susceptible to a Time-of-Check Time-of-Use (TOCTOU) race condition. This means that the application verifies the path of a file before reading it, but an attacker can potentially modify the file path in between the check and the read operation. The vulnerability was reported by AntAISecurityLab and patched in version 2026.3.31. Successful exploitation allows attackers to escape the sandbox, potentially leading to arbitrary code execution on the host system.

## Attack Chain

1. The attacker crafts a request to the OpenClaw application, specifying a file path within the allowed sandbox.
2. OpenClaw's `readFile` function receives the request and validates that the requested path is within the allowed sandbox.
3. After the path is validated, but before the file is read, the attacker leverages a race condition to modify the file path. This could be achieved by symlink replacement or other file system manipulation techniques.
4. The `readFile` function now attempts to read the file from the modified path, which could point to a location outside the intended sandbox.
5. The file from the attacker-controlled path is read, bypassing the initial security check.
6. OpenClaw processes the content of the file, potentially executing malicious code or leaking sensitive information, depending on the file's contents and the application's handling of it.
7. The attacker successfully escapes the sandbox, gaining unauthorized access to the host system's resources.

## Impact

Successful exploitation of this TOCTOU vulnerability allows an attacker to bypass the intended security restrictions of the OpenClaw sandbox. This can lead to arbitrary code execution on the host system, potentially allowing the attacker to install malware, steal sensitive data, or pivot to other systems on the network. While the specific number of affected installations is unknown, all deployments of OpenClaw versions 2026.3.28 or earlier are vulnerable.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to patch the vulnerability as indicated in the advisory.
*   Deploy the provided Sigma rule to detect attempts to exploit this TOCTOU vulnerability by monitoring file access patterns.
*   Enable file integrity monitoring (FIM) on critical system files to detect unauthorized modifications that could indicate exploitation attempts.

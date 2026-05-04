---
title: OpenClaw Symlink Race Condition Allows Sandbox Escape
slug: 2024-01-openclaw-symlink
description: A time-of-check/time-of-use (TOCTOU) race condition in OpenClaw versions 2026.4.21 and earlier allows a symlink swap to redirect filesystem writes outside the intended sandbox mount root, potentially leading to arbitrary file modification.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sandbox-escape
  - symlink
  - race-condition
  - npm
vendors:
  - npm
products:
  - openclaw (<= 2026.4.21)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-wppj-c6mr-83jj
rules:
  - title: Detect OpenClaw Sandbox Escape via Symlink
    description: Detects potential attempts to exploit the OpenClaw sandbox escape vulnerability by monitoring for file writes outside the intended sandbox directory after a symlink operation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 1
---

OpenClaw, a tool available via npm, contains a vulnerability in versions 2026.4.21 and earlier that could allow for a sandbox escape. This vulnerability stems from a time-of-check/time-of-use (TOCTOU) race condition during filesystem writes within the OpenShell sandbox environment. An attacker could potentially exploit this vulnerability by manipulating symlinks to redirect write operations outside of the intended local mount root. This can occur because OpenClaw does not properly validate the target of write operations against the mount root, leaving it susceptible to symlink-based redirection attacks. Successful exploitation could allow an attacker to modify sensitive files outside the sandbox. The vulnerability is fixed in version 2026.4.22.

## Attack Chain

1. An attacker crafts a malicious OpenClaw package or leverages an existing package.
2. The package contains a symlink within the intended sandbox directory.
3. The OpenClaw application attempts to write to a file via the symlink.
4. Between the time OpenClaw checks the symlink and the time it performs the write operation, the attacker replaces the symlink with a new symlink pointing outside the intended sandbox root.
5. OpenClaw, due to the TOCTOU race condition, writes to the file location pointed to by the new symlink, which resides outside the sandbox.
6. This allows the attacker to overwrite or modify arbitrary files on the system.
7. The attacker leverages this capability to gain elevated privileges or compromise sensitive data.

## Impact

Successful exploitation of this vulnerability could allow an attacker to bypass the intended security restrictions of the OpenClaw sandbox. An attacker could potentially overwrite system files, inject malicious code into existing applications, or steal sensitive data. While the exact number of affected installations is unknown, any system running a vulnerable version of OpenClaw is susceptible to this attack.

## Recommendation

*   Upgrade to OpenClaw version 2026.4.22 or later to patch the vulnerability (reference: Affected Packages / Versions).
*   Monitor file system events for unexpected modifications outside of the expected OpenClaw sandbox directory. Deploy the Sigma rule `Detect OpenClaw Sandbox Escape via Symlink` to detect potential exploitation attempts.
*   Implement stricter file system access controls to limit the potential impact of successful exploitation (reference: Impact).

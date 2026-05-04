---
title: OpenClaw MCP Loopback Token Spoofing Vulnerability
slug: 2024-01-openclaw-token-spoofing
description: A vulnerability in OpenClaw versions 2026.4.21 and earlier allows a non-owner loopback client to spoof the owner context by manipulating request headers, potentially gaining unauthorized access to owner-gated operations.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - npm
  - token spoofing
vendors:
  - npm
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-r6xh-pqhr-v4xh
rules:
  - title: Detect OpenClaw MCP Loopback Owner Spoofing
    description: Detects HTTP requests with suspicious 'sender-owner' headers targeting MCP loopback endpoints, indicating potential owner spoofing attempts in vulnerable OpenClaw instances.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Version via User-Agent
    description: Detects requests from OpenClaw based on user agent strings.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a package available on npm, contains a vulnerability in versions 2026.4.21 and earlier that allows for token spoofing within the MCP loopback path. This flaw stems from the acceptance of spoofable owner-context metadata from request headers. A malicious actor could exploit this by crafting requests that falsely present them as the owner, thereby bypassing authorization checks and potentially gaining unauthorized access to operations intended only for the owner. The vulnerability was reported by @VladimirEliTokarev and patched in version 2026.4.22. This issue matters for defenders because it can lead to privilege escalation and unauthorized modification of system configurations or data.

## Attack Chain

1.  Attacker identifies a vulnerable OpenClaw instance (version <= 2026.4.21) utilizing the MCP loopback.
2.  Attacker crafts a malicious HTTP request targeting the MCP loopback endpoint.
3.  Attacker injects a forged "sender-owner" header into the HTTP request, claiming owner privileges.
4.  The vulnerable OpenClaw instance incorrectly trusts the spoofed "sender-owner" header.
5.  The application bypasses owner authorization checks due to the forged header.
6.  Attacker gains access to owner-gated operations within the MCP loopback.
7.  Attacker performs unauthorized actions, such as modifying configurations or accessing sensitive data.
8.  Attacker maintains unauthorized access, potentially escalating privileges further within the system.

## Impact

Successful exploitation of this vulnerability could allow unauthorized access to critical system functions intended only for the owner. This could lead to configuration changes, data breaches, or other malicious activities depending on the specific owner-gated operations exposed within the OpenClaw MCP loopback. The severity depends on the permissions granted to the "owner" context within the application but could be critical.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.22 or later to remediate the vulnerability as described in the fix commit 3cb1a56bfc9579a0f2336f9cfa12a8a744332a19.
*   Implement network monitoring to detect suspicious HTTP requests containing potentially forged "sender-owner" headers targeting MCP loopback endpoints using the Sigma rule `Detect OpenClaw MCP Loopback Owner Spoofing`.
*   Review and audit existing OpenClaw deployments to identify and patch vulnerable instances quickly.

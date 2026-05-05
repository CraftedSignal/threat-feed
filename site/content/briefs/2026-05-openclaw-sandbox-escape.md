---
title: OpenClaw Sandbox Escape Vulnerability (CVE-2026-42434)
slug: 2026-05-openclaw-sandbox-escape
description: OpenClaw versions 2026.4.5 before 2026.4.10 contain a sandbox escape vulnerability (CVE-2026-42434) that allows attackers to bypass sandbox boundaries and route execution to remote nodes by overriding exec routing.
date: "2026-05-05T12:16:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sandbox escape
  - privilege escalation
  - cve-2026-42434
vendors:
  - OpenClaw
products:
  - OpenClaw (>= 2026.4.5, < 2026.4.10)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-42434
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42434
  - https://github.com/openclaw/openclaw/commit/dffad08529202edbf34e4808788e1182fe10f6a9
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-736r-jwj6-4w23
  - https://www.vulncheck.com/advisories/openclaw-sandbox-escape-via-host-parameter-override-in-exec-routing
rules:
  - title: Detect OpenClaw Suspicious Exec Routing with Host Override
    description: Detects suspicious OpenClaw exec routing requests where the host parameter is set to 'node', potentially indicating a sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Suspicious Exec Routing Parameters
    description: Detects suspicious OpenClaw exec routing requests containing unusual characters or commands
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions 2026.4.5 before 2026.4.10 are vulnerable to a sandbox escape vulnerability, identified as CVE-2026-42434. This flaw allows attackers to bypass the intended sandbox boundaries. By exploiting this vulnerability, a sandboxed agent can override the exec routing mechanism, directing execution to unintended remote nodes instead of the intended sandbox paths. This could lead to unauthorized access and control over the OpenClaw environment. This vulnerability was reported on May 5th, 2026.

## Attack Chain

1. An attacker gains initial access to a sandboxed OpenClaw agent.
2. The attacker crafts a malicious request to execute a command.
3. The request includes a manipulated `host` parameter set to `node`, overriding the intended execution path.
4. OpenClaw's exec routing mechanism incorrectly processes the request due to the vulnerability in versions prior to 2026.4.10.
5. Instead of executing within the sandbox, the command is routed to a remote node.
6. The remote node executes the command with the privileges of the OpenClaw agent.
7. The attacker gains unauthorized access and control over the remote node.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass sandbox restrictions within OpenClaw. This can lead to privilege escalation and unauthorized access to sensitive resources on remote nodes. The impact includes potential data breaches, system compromise, and the ability to execute arbitrary code outside the intended sandbox environment.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.10 or later to patch CVE-2026-42434.
*   Monitor OpenClaw agent logs for suspicious exec routing requests, especially those with `host=node` parameters.
*   Implement network segmentation to limit the impact of compromised nodes.

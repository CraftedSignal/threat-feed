---
title: OpenClaw ACP Chat Command Injection Vulnerability
slug: 2026-06-openclaw-acp-bypass
description: A vulnerability in the openclaw npm package before version 2026.3.22 allowed mutating internal ACP chat commands without requiring operator.admin scope enforcement, potentially allowing unauthorized control-plane actions.
date: "2026-03-26T21:25:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - acp
  - chat-command-injection
  - vulnerability
references:
  - https://github.com/advisories/GHSA-3w6x-gv34-mqpf
rules:
  - title: OpenClaw ACP Command Execution Without Admin Scope
    description: Detects attempts to execute OpenClaw ACP commands without the required operator.admin scope.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    data_sources:
      - application
      - openclaw
  - title: OpenClaw Suspicious ACP Command Activity
    description: Detects potentially malicious activity through OpenClaw ACP commands.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - discovery
    data_sources:
      - application
      - openclaw
rules_count: 2
---

The `openclaw` npm package, versions prior to 2026.3.22, contained a vulnerability where internal ACP (Admin Control Panel) chat commands could be mutated without proper `operator.admin` scope enforcement. This flaw could be exploited by an attacker to bypass intended security controls and execute unauthorized administrative actions within the OpenClaw application. The vulnerability was reported by @tdjackey and patched in version 2026.3.22. Defenders should ensure they are running version 2026.3.22 or later to mitigate this risk. The scope of impact is limited to systems running vulnerable versions of the `openclaw` package.

## Attack Chain

1.  Attacker identifies an instance of OpenClaw running a version prior to 2026.3.22.
2.  Attacker crafts a malicious chat command intended to interact with the ACP.
3.  The malicious command bypasses the intended `operator.admin` scope check due to the vulnerability.
4.  The crafted command is sent to the OpenClaw application via the chat interface.
5.  The vulnerable code in `src/auto-reply/reply/commands-acp.ts` processes the command without proper authorization.
6.  The command execution results in the mutation of internal ACP configurations or data.
7.  Attacker leverages the mutated configurations to gain further control over the OpenClaw application or its environment.

## Impact

Successful exploitation of this vulnerability could allow an attacker to perform unauthorized administrative actions within the OpenClaw application. This may include modifying application settings, accessing sensitive data, or disrupting services. The severity of the impact depends on the specific ACP commands that are exposed and the attacker's ability to chain together multiple commands for greater effect.

## Recommendation

*   Upgrade the `openclaw` npm package to version 2026.3.22 or later to apply the fix described in the advisory (see Affected Packages / Versions).
*   Monitor chat command inputs for unusual syntax or attempts to access administrative functionalities to detect potential exploitation attempts (use network or application logs).
*   Review and audit existing OpenClaw configurations for any unauthorized modifications that may have occurred due to this vulnerability.
*   Implement input validation and sanitization on all chat command inputs to prevent command injection attacks.
*   Deploy the Sigma rule provided to detect attempts to use ACP commands without proper authorization (see "OpenClaw ACP Command Execution Without Admin Scope").

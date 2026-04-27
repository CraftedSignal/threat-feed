---
title: OpenClaw ACP Chat Command Injection Vulnerability
slug: 2026-06-openclaw-acp-bypass
description: A vulnerability in the openclaw npm package before version 2026.3.22 allowed mutating internal ACP chat commands without requiring operator.admin scope enforcement, potentially allowing unauthorized control-plane actions.
date: "2026-03-26T21:25:00Z"
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

The `openclaw` npm package, versions prior to 2026.3.22, contained a vulnerability where internal ACP (Admin Control Panel) chat commands could be mutated without proper `operator.admin` scope enforcement. This flaw could be exploited by an attacker to bypass intended security controls and execute unauthorized administrative actions within the OpenClaw application. The vulnerability was reported by @tdjackey and patched in version 2026.3.22. Defenders should ensure they are running version…

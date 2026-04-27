---
title: OpenClaw Gateway Unauthorized Session Reset Vulnerability
slug: 2026-04-openclaw-session-reset
description: A vulnerability in OpenClaw Gateway allows a write-scoped gateway caller to rotate a target session, archive the prior transcript state, and force a new session id without admin scope via the `chat.send` path by reusing command authorization to trigger `/reset` session rotation.
date: "2026-04-01T00:00:34Z"
severities:
  - high
tags:
  - openclaw
  - session-reset
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-5r8f-96gm-5j6g
rules:
  - title: Detect OpenClaw Gateway Chat Send Reset Command
    description: Detects chat.send requests that may trigger a session reset due to command authorization vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Gateway Session Reset via API
    description: Detects direct attempts to reset a session via the OpenClaw Gateway API, which should be restricted to administrators.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw Gateway versions 2026.3.24 and earlier contain a vulnerability that allows unauthorized session resets. A write-scoped gateway caller can exploit this flaw to rotate a target session, archive the prior transcript state, and force a new session ID, actions that should be restricted to administrative users. This is possible because the `chat.send` path incorrectly reuses command authorization checks when triggering the `/reset` functionality. Defenders should upgrade to version 2026.3.28…

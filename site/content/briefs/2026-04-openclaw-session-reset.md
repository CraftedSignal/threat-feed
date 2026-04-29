---
title: OpenClaw Gateway Unauthorized Session Reset Vulnerability
slug: 2026-04-openclaw-session-reset
description: A vulnerability in OpenClaw Gateway allows a write-scoped gateway caller to rotate a target session, archive the prior transcript state, and force a new session id without admin scope via the `chat.send` path by reusing command authorization to trigger `/reset` session rotation.
date: "2026-04-01T00:00:34Z"
type: coverage
types:
  - coverage
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

OpenClaw Gateway versions 2026.3.24 and earlier contain a vulnerability that allows unauthorized session resets. A write-scoped gateway caller can exploit this flaw to rotate a target session, archive the prior transcript state, and force a new session ID, actions that should be restricted to administrative users. This is possible because the `chat.send` path incorrectly reuses command authorization checks when triggering the `/reset` functionality. Defenders should upgrade to version 2026.3.28 or later to remediate this vulnerability. This issue affects deployments where write-scoped callers should not have the ability to reset sessions.

## Attack Chain

1. Attacker identifies an OpenClaw Gateway instance running a vulnerable version (<= 2026.3.24).
2. Attacker obtains valid credentials for a gateway caller with write scope permissions.
3. Attacker crafts a `chat.send` request.
4. The `chat.send` request is designed to trigger the `/reset` command within the application.
5. The application incorrectly authorizes the `/reset` command based on the write scope of the `chat.send` request.
6. The target session is rotated, archiving the previous transcript state.
7. A new session ID is forced for the target.
8. The attacker effectively resets the target session without requiring admin-level privileges.

## Impact

Successful exploitation of this vulnerability allows a write-scoped caller to perform administrative actions, specifically session resets. This could lead to disruption of service, unauthorized access to archived session data, or other unforeseen consequences depending on the specific implementation of OpenClaw Gateway. If an attacker can repeatedly reset sessions, it could create a denial-of-service condition.

## Recommendation

*   Upgrade OpenClaw Gateway to version 2026.3.28 or later to patch the vulnerability described in [GHSA-5r8f-96gm-5j6g](https://github.com/advisories/GHSA-5r8f-96gm-5j6g).
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts.
*   Review the commit `be00fcfccb` to understand the fix and identify any potential backporting needs.

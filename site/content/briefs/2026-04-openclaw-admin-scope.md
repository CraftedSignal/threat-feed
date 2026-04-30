---
title: OpenClaw Gateway Plugin Subagent Admin Scope Vulnerability
slug: 2026-04-openclaw-admin-scope
description: The openclaw package versions 2026.3.24 and earlier are vulnerable due to the gateway plugin subagent fallback `deleteSession` function dispatching `sessions.delete` with a synthetic `operator.admin` runtime scope, potentially leading to unauthorized session deletion.
date: "2026-03-29T15:50:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - vulnerability
  - authorization
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-h4jx-hjr3-fhgc
rules:
  - title: Detect OpenClaw Admin Scope Session Deletion
    description: Detects calls to deleteSession with a synthetic operator.admin scope within OpenClaw. This may indicate exploitation of the vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
  - title: OpenClaw deleteSession Fallback Without Client Context
    description: Detects when the deleteSession function in OpenClaw is called without a valid client context, potentially leading to the use of a synthetic admin scope.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
rules_count: 2
---

The `openclaw` package, specifically versions up to and including 2026.3.24, contains a vulnerability within the gateway plugin subagent fallback mechanism. The `deleteSession` function, when invoked without a request-scoped client, incorrectly dispatched `sessions.delete` utilizing a synthetic `operator.admin` runtime scope. This means that under certain conditions, session deletion operations were being performed with elevated privileges, potentially leading to unauthorized session management. This vulnerability was present in the code up to version 2026.3.24 and has been patched in version 2026.3.25. Defenders should ensure they are running version 2026.3.25 or later to mitigate this risk.

## Attack Chain

1. A request is made to the gateway plugin that triggers the `deleteSession` function.
2. The `deleteSession` function checks for a request-scoped client.
3. If no request-scoped client exists, the code falls back to a default mechanism.
4. The vulnerable code path then incorrectly creates a synthetic `operator.admin` runtime scope.
5. The `sessions.delete` function is dispatched with the elevated `operator.admin` scope.
6. Session deletion occurs with the privileges of the synthetic admin operator.
7. An attacker could potentially trigger this code path to delete sessions they should not have access to.

## Impact

Successful exploitation of this vulnerability could lead to unauthorized session deletion within the `openclaw` application. While the exact impact depends on the specific deployment and usage of `openclaw`, the ability to delete arbitrary sessions could disrupt service availability or allow an attacker to invalidate legitimate user sessions. If an attacker can reliably trigger this vulnerability, it could lead to denial-of-service or other forms of service disruption.

## Recommendation

*   Upgrade the `openclaw` package to version 2026.3.25 or later to remediate the vulnerability described in the overview.
*   Review the `openclaw` codebase and audit the usage of `deleteSession` to identify any potential misuse or unexpected invocations.

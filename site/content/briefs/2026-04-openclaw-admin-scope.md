---
title: OpenClaw Gateway Plugin Subagent Admin Scope Vulnerability
slug: 2026-04-openclaw-admin-scope
description: The openclaw package versions 2026.3.24 and earlier are vulnerable due to the gateway plugin subagent fallback `deleteSession` function dispatching `sessions.delete` with a synthetic `operator.admin` runtime scope, potentially leading to unauthorized session deletion.
date: "2026-03-29T15:50:41Z"
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

The `openclaw` package, specifically versions up to and including 2026.3.24, contains a vulnerability within the gateway plugin subagent fallback mechanism. The `deleteSession` function, when invoked without a request-scoped client, incorrectly dispatched `sessions.delete` utilizing a synthetic `operator.admin` runtime scope. This means that under certain conditions, session deletion operations were being performed with elevated privileges, potentially leading to unauthorized session…

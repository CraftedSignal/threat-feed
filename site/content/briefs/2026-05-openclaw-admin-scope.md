---
title: OpenClaw Gateway Plugin Grants Unrestricted operator.admin Runtime Scope
slug: 2026-05-openclaw-admin-scope
description: The openclaw gateway plugin versions 2026.3.24 and earlier incorrectly grants operator.admin runtime scope to all callers, regardless of their granted scopes, potentially allowing unauthorized actions.
date: "2026-03-27T22:32:36Z"
severities:
  - high
tags:
  - openclaw
  - privilege-escalation
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-qm2m-28pf-hgjw
rules:
  - title: Detect OpenClaw Admin Operations from Non-Admin Sources
    description: Detects OpenClaw administrative operations being executed by users or systems that should not have administrator privileges based on source IP.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Potential OpenClaw Operator Admin Scope Abuse
    description: Detects API calls using the 'operator.admin' scope originating from unusual sources after OpenClaw authentication.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The OpenClaw gateway plugin, specifically in versions up to and including 2026.3.24, contains a vulnerability related to runtime scope management. This flaw allows any caller interacting with the gateway to be granted the `operator.admin` scope, irrespective of the permissions they should possess. This means that users or systems with limited access can potentially perform administrative actions within the OpenClaw environment. This vulnerability was resolved in version 2026.3.25 with the…

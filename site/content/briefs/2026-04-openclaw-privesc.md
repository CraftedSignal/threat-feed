---
title: OpenClaw Privilege Escalation via Backend Reconnect
slug: 2026-04-openclaw-privesc
description: A critical privilege escalation vulnerability in OpenClaw allows non-admin operators to self-claim admin privileges by exploiting a flaw in gateway backend reconnect handling.
date: "2026-03-27T22:48:49Z"
severities:
  - critical
tags:
  - privilege-escalation
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-9hjh-fr4f-gxc4
rules:
  - title: Detect OpenClaw Backend Reconnect Requesting Admin Scope
    description: Detects attempts to reconnect to OpenClaw backend requesting operator.admin scope which is indicative of potential privilege escalation attempt in vulnerable versions.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Elevated Privileges Granted to Backend
    description: Detects events where a backend is granted elevated privileges in OpenClaw, which could be a sign of successful exploitation of the privilege escalation vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions 2026.3.24 and earlier contain a critical vulnerability that allows a non-admin operator to escalate their privileges to that of an administrator. This is achieved through a flaw in the gateway backend reconnect process, where backend-labeled reconnects can self-request broader scopes, specifically `operator.admin`, effectively bypassing the intended pairing mechanism. This allows an attacker with limited operator privileges to gain full administrative control over the OpenClaw…

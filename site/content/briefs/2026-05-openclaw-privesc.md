---
title: OpenClaw Incomplete Scope Clearing Allows Privilege Escalation
slug: 2026-05-openclaw-privesc
description: An incomplete fix in OpenClaw versions 2026.3.28 and earlier allows for operator.admin privilege escalation via trusted-proxy authentication mode, which is fixed in version 2026.3.31.
date: "2026-04-03T03:06:12Z"
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-g374-mggx-p6xc
rules:
  - title: Detect OpenClaw operator.admin Escalation via Trusted Proxy
    description: Detects potential privilege escalation attempts in OpenClaw by monitoring for unauthorized access attempts to sensitive API endpoints after trusted proxy authentication.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Failed Admin Access after Trusted Proxy Auth
    description: Detects potential failed privilege escalation attempts in OpenClaw by monitoring for failed access attempts to sensitive API endpoints after trusted proxy authentication (may indicate reconnaissance).
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A high-severity vulnerability exists in the OpenClaw npm package, specifically affecting versions 2026.3.28 and earlier. This vulnerability arises from an incomplete fix related to scope clearing within the trusted-proxy authentication mode. The flaw allows attackers to escalate their privileges to operator.admin, potentially gaining unauthorized access to sensitive data or system functionalities. The vulnerability was reported by @north-echo and patched in version 2026.3.31, with the fix…

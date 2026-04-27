---
title: OpenClaw Sandbox Bypass via Heartbeat Context Inheritance
slug: 2026-04-openclaw-sandbox-bypass
description: A critical vulnerability in the openclaw npm package (<=2026.3.28) allows a heartbeat context inheritance to bypass the sandbox via senderIsOwner escalation, patched in version 2026.3.31.
date: "2026-04-02T20:59:29Z"
severities:
  - critical
tags:
  - sandbox-bypass
  - dependency-vulnerability
  - npm
references:
  - https://github.com/advisories/GHSA-g5cg-8x5w-7jpm
rules:
  - title: Detect OpenClaw Sandbox Bypass Attempt via senderIsOwner Escalation
    description: Detects potential attempts to exploit the OpenClaw sandbox bypass vulnerability by monitoring for suspicious process creations originating from openclaw modules with commands that might indicate privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of OpenClaw Configuration Files
    description: Detects attempts to modify OpenClaw configuration files, which might be indicative of an exploit attempt.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `openclaw` npm package, a tool used for [describe package functionality if known, else leave generic], contains a critical vulnerability related to how heartbeat contexts are inherited. Specifically, improper handling of the `senderIsOwner` property during context inheritance allows a malicious actor to bypass intended sandbox restrictions. This vulnerability affects `openclaw` versions up to and including 2026.3.28. This issue was reported by @AntAISecurityLab and patched in version…

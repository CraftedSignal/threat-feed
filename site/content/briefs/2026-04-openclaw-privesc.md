---
title: OpenClaw Privilege Escalation via Unbound Bootstrap Codes
slug: 2026-04-openclaw-privesc
description: OpenClaw versions 2026.3.13-1 and earlier contain a privilege escalation vulnerability where bootstrap setup codes are not properly bound, allowing attackers to gain elevated privileges during the initial device pairing process.
date: "2026-04-03T03:19:33Z"
severities:
  - high
tags:
  - privilege-escalation
  - npm
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-gg9v-mgcp-v6m7
rules:
  - title: Detect OpenClaw Package Install from Public Registry
    description: Detects installation of the OpenClaw package from the public npm registry, which could indicate an initial deployment or update.
    platform: sigma
    severity: informational
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw Version Check via NPM
    description: Detects attempts to check the installed version of OpenClaw using npm, which might precede exploitation attempts or reconnaissance.
    platform: sigma
    severity: informational
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A high-severity privilege escalation vulnerability affects the OpenClaw npm package. Specifically, versions up to and including 2026.3.13-1 are vulnerable. The flaw stems from a lack of proper binding for bootstrap setup codes, which are used during the initial device pairing. This allows an attacker to potentially escalate privileges during the first-time setup process. The vulnerability was reported by @tdjackey and patched in version 2026.3.22, with the fix committed on March 22, 2026…

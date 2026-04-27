---
title: OpenClaw RCE via Build Tool Environment Variable Injection
slug: 2024-01-09-openclaw-rce
description: OpenClaw versions prior to 2026.4.8 are vulnerable to remote code execution (RCE) via build tool environment variable injection due to missing denylist entries for HGRCPATH, CARGO_BUILD_RUSTC_WRAPPER, RUSTC_WRAPPER, and MAKEFLAGS, allowing hostile environment variables to influence host exec commands.
date: "2026-04-09T14:22:29Z"
severities:
  - high
tags:
  - rce
  - environment-variable-injection
  - openclaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569.002
    technique_name: 'System Services: Service Execution'
references:
  - https://github.com/advisories/GHSA-7437-7hg8-frrw
rules:
  - title: Detect Suspicious Process Creation from OpenClaw
    description: Detects suspicious processes spawned by OpenClaw, potentially indicating RCE.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Environment Variable Manipulation via OpenClaw
    description: Detects unusual environment variable usage in OpenClaw processes, potentially indicating environment variable injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw, a user-controlled local assistant, is vulnerable to a remote code execution (RCE) issue affecting versions prior to 2026.4.8. The vulnerability, identified as GHSA-cm8v-2vh9-cxf3, stems from missing denylist entries for environment variables that influence build tools. Specifically, HGRCPATH, CARGO_BUILD_RUSTC_WRAPPER, RUSTC_WRAPPER, and MAKEFLAGS were not properly sanitized, allowing a malicious actor to inject arbitrary commands into the build process. This can lead to the execution…

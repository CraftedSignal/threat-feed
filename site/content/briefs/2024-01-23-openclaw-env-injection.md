---
title: OpenClaw Environment Variable Injection Vulnerability
slug: 2024-01-23-openclaw-env-injection
description: The openclaw package versions prior to 2026.4.10 are vulnerable to environment variable injection, where the exec environment policy missed interpreter startup variables allowing operator-supplied environment overrides to influence downstream execution or network behavior, addressed in versions 2026.4.10 and later.
date: "2026-04-17T21:54:20Z"
severities:
  - high
tags:
  - npm
  - openclaw
  - environment-variable-injection
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://github.com/advisories/GHSA-vfp4-8x56-j7c5
rules:
  - title: Detect Process Execution with Suspicious Environment Variables
    description: Detects process execution with environment variables that may indicate an attempt to exploit the openclaw vulnerability
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - windows
  - title: Detect Process Execution with HOSTALIASES Environment Variable
    description: Detects process execution with HOSTALIASES variable
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `openclaw` package, a tool used within the npm ecosystem, was found to have a vulnerability affecting versions prior to 2026.4.10. This vulnerability stems from an inadequate environment variable denylist in the exec environment policy. Specifically, the policy failed to block high-risk interpreter startup variables such as `VIMINIT`, `EXINIT`, `LUA_INIT`, and `HOSTALIASES`. This oversight allowed malicious actors to potentially inject arbitrary environment variables, thereby influencing…

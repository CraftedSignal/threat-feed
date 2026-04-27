---
title: goshs Authentication Bypass Vulnerability (CVE-2026-34581)
slug: 2026-04-goshs-auth-bypass
description: goshs versions 1.1.0 to before 2.0.0-beta.2 are vulnerable to authentication bypass via Share Token, potentially allowing code execution (CVE-2026-34581).
date: "2026-04-02T19:21:32Z"
severities:
  - high
tags:
  - cve-2026-34581
  - authentication-bypass
  - code-execution
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34581
  - https://github.com/patrickhener/goshs/commit/6fb224ed15c2ccc0c61a5ebe22f2401eb06e9216
  - https://github.com/patrickhener/goshs/releases/tag/v2.0.0-beta.2
  - https://github.com/patrickhener/goshs/security/advisories/GHSA-jgfx-74g2-9r6g
rules:
  - title: Detect Goshs Code Execution via Auth Bypass
    description: Detects potential attempts to exploit the authentication bypass vulnerability in goshs leading to code execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 1
---

CVE-2026-34581 affects goshs, a SimpleHTTPServer written in Go. Versions 1.1.0 to before 2.0.0-beta.2 are susceptible to an authentication bypass vulnerability. When a user attempts to access the server with a Share Token, it is possible to bypass the intended file download restriction, gaining access to all goshs functionalities. This includes the ability to execute arbitrary code on the server. The vulnerability was patched in version 2.0.0-beta.2. This vulnerability allows unauthenticated…

---
title: OpenClaw Incorrect Authorization Vulnerability (CVE-2026-35653)
slug: 2026-04-openclaw-auth-bypass
description: OpenClaw before 2026.3.24 contains an incorrect authorization vulnerability in the POST /reset-profile endpoint, allowing authenticated callers with operator.write access to browser.request to bypass profile mutation restrictions and escalate privileges.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - vulnerability
  - authorization bypass
  - privilege escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-35653
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35653
  - https://github.com/openclaw/openclaw/commit/4dcc39c25c6cc63fedfd004f52d173716576fcf0
  - https://github.com/openclaw/openclaw/commit/e7d11f6c33e223a0dd8a21cfe01076bd76cef87a
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-xp9r-prpg-373r
  - https://www.vulncheck.com/advisories/openclaw-incorrect-authorization-in-post-reset-profile-via-browser-request
rules:
  - title: Detect OpenClaw Profile Reset Attempt
    description: Detects POST requests to the /reset-profile endpoint, potentially indicating an attempted exploitation of CVE-2026-35653.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
      - T1548.001
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Profile Directory Manipulation
    description: Detects file operations indicative of unauthorized profile directory manipulation in OpenClaw.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw, a software application of unknown purpose, is susceptible to an incorrect authorization vulnerability tracked as CVE-2026-35653. This flaw affects versions prior to 2026.3.24. The vulnerability lies within the `/reset-profile` endpoint, specifically when accessed via a POST request. An authenticated user with `operator.write` access combined with `browser.request` permissions can exploit this to bypass intended profile mutation restrictions. This bypass allows the attacker to perform…

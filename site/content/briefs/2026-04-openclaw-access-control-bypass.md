---
title: OpenClaw Improper Access Control Vulnerability (CVE-2026-34512)
slug: 2026-04-openclaw-access-control-bypass
description: OpenClaw before 2026.3.25 contains an improper access control vulnerability (CVE-2026-34512) in the HTTP /sessions/:sessionKey/kill route, allowing any authenticated user to terminate arbitrary subagent sessions.
date: "2026-04-09T22:16:29Z"
severities:
  - high
tags:
  - access-control
  - vulnerability
  - webserver
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-34512
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34512
  - https://github.com/openclaw/openclaw/commit/02cf12371f9353a16455da01cc02e6c4ecfc4152
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-9p93-7j67-5pc2
  - https://www.vulncheck.com/advisories/openclaw-improper-access-control-in-sessions-sessionkey-kill-endpoint
rules:
  - title: Detect OpenClaw Unauthorized Session Termination
    description: Detects attempts to exploit CVE-2026-34512 by monitoring for POST requests to the /sessions/:sessionKey/kill endpoint, which could indicate unauthorized session termination attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Session Key Enumeration
    description: Detects potential reconnaissance activity by monitoring for requests listing or accessing multiple session keys, which could be an attacker identifying valid session IDs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.25 are susceptible to an improper access control vulnerability, tracked as CVE-2026-34512. This flaw resides in the `/sessions/:sessionKey/kill` HTTP route and allows any bearer-authenticated user, regardless of their assigned privileges, to execute admin-level session termination functions. The vulnerability stems from a lack of proper scope validation, enabling attackers to bypass intended ownership and operator scope restrictions. By sending crafted…

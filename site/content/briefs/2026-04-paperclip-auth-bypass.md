---
title: Paperclip Unauthenticated API Access Vulnerability
slug: 2026-04-paperclip-auth-bypass
description: Paperclip application suffers from multiple unauthenticated API access vulnerabilities allowing attackers to access sensitive data, gather reconnaissance, and potentially bypass authentication.
date: "2026-04-17T12:00:00Z"
severities:
  - high
tags:
  - paperclip
  - authentication-bypass
  - api-vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-xfqj-r5qw-8g4j
rules:
  - title: Detect Paperclip Unauthenticated Health Endpoint Access
    description: Detects unauthenticated access to the /api/health endpoint, which may indicate reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Detect Paperclip Unauthenticated Skill Endpoint Access
    description: Detects unauthenticated access to the /api/skills/index endpoint, which may indicate reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Paperclip, a software application, contains multiple API endpoints that lack proper authentication checks, even when the application is configured in "authenticated" mode. This vulnerability allows unauthenticated access to sensitive information and functionality. Observed in versions prior to 2026.416.0, the issue impacts the confidentiality and integrity of the application. An attacker can exploit these vulnerabilities to gather reconnaissance information about the deployment, access…

---
title: Chartbrew Cross-Tenant Authorization Bypass Vulnerability
slug: 2024-01-03-chartbrew-auth-bypass
description: Chartbrew versions prior to 4.9.0 are vulnerable to a cross-tenant authorization bypass, allowing an authenticated attacker to access project data belonging to other teams.
date: "2026-04-10T20:16:21Z"
severities:
  - high
tags:
  - chartbrew
  - authorization-bypass
  - web-application
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1587
    technique_name: Develop Capabilities
cves:
  - id: CVE-2026-32252
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32252
rules:
  - title: Detect Chartbrew Template Generation Request
    description: Detects requests to the Chartbrew template generation endpoint which is vulnerable to authorization bypass.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1587.001
    data_sources:
      - webserver
      - linux
  - title: Detect Chartbrew Unauthenticated Template Generation Request
    description: Detects unauthenticated requests to the Chartbrew template generation endpoint which is vulnerable to authorization bypass.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1587.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chartbrew, an open-source web application used for creating charts from databases and APIs, is vulnerable to a cross-tenant authorization bypass (CVE-2026-32252) in versions prior to 4.9.0. This vulnerability resides in the GET /team/:team_id/template/generate/:project_id endpoint. Specifically, the `checkAccess` function doesn't await its promise and fails to validate if the `project_id` belongs to the specified `team_id` or the attacker's team. This allows an authenticated attacker with…

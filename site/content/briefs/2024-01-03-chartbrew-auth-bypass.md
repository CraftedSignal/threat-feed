---
title: Chartbrew Cross-Tenant Authorization Bypass Vulnerability
slug: 2024-01-03-chartbrew-auth-bypass
description: Chartbrew versions prior to 4.9.0 are vulnerable to a cross-tenant authorization bypass, allowing an authenticated attacker to access project data belonging to other teams.
date: "2026-04-10T20:16:21Z"
type: advisory
types:
  - advisory
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

Chartbrew, an open-source web application used for creating charts from databases and APIs, is vulnerable to a cross-tenant authorization bypass (CVE-2026-32252) in versions prior to 4.9.0. This vulnerability resides in the GET /team/:team_id/template/generate/:project_id endpoint. Specifically, the `checkAccess` function doesn't await its promise and fails to validate if the `project_id` belongs to the specified `team_id` or the attacker's team. This allows an authenticated attacker with template generation permissions in their own team to request and receive template model data for projects belonging to other teams. Upgrading to version 4.9.0 or later resolves this issue.

## Attack Chain

1. Attacker authenticates to a Chartbrew instance with valid credentials and template generation permissions within their own team.
2. Attacker identifies a valid `team_id` belonging to a victim team. This could be done through enumeration of team IDs, social engineering, or other means.
3. Attacker identifies a valid `project_id` belonging to the victim team. This may require some level of prior knowledge or reconnaissance.
4. Attacker crafts a GET request to `/team/:victim_team_id/template/generate/:victim_project_id`, replacing `:victim_team_id` and `:victim_project_id` with the identified values.
5. The Chartbrew server receives the request and calls the `checkAccess` function, but does not await the promise.
6. Due to the missing validation of the `project_id` against the `team_id` and the caller's team, the authorization check is bypassed.
7. The server retrieves the template model data associated with the victim's project.
8. The server returns the victim's project data to the attacker.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain unauthorized access to sensitive project data belonging to other teams within the Chartbrew application. This could include confidential database connection strings, API keys, data schemas, and other information that could be used to further compromise the victim's systems or data. The number of affected organizations depends on the adoption rate of Chartbrew instances prior to version 4.9.0.

## Recommendation

*   Upgrade Chartbrew to version 4.9.0 or later to patch CVE-2026-32252.
*   Implement the Sigma rule `Detect Chartbrew Template Generation Request` to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for unusual requests to the `/team/*/template/generate/*` endpoint using a WAF or similar tool.

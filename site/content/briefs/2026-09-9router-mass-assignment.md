---
title: Authentication Bypass in 9router via Mass Assignment
slug: 2026-09-9router-mass-assignment
description: 9router versions 0.5.2 and earlier are vulnerable to mass assignment in the PATCH /api/settings endpoint, allowing an authenticated user to disable authentication globally and access protected API routes.
date: "2026-09-23T19:57:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:9router:9router:*:*:*:*:*:*:*:*
tags:
  - mass-assignment
  - cve
  - authentication-bypass
vendors:
  - 9router
products:
  - 9router (<= 0.5.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated user can set security-critical fields that are not meant to be modifiable here, notably requireLogin, which disables authentication for the whole application.
    confidence_band: high
cves:
  - id: CVE-2026-56679
    epss: 0.00519
references:
  - https://github.com/advisories/GHSA-vmjq-hvgq-2wv4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56679
rules:
  - title: Detect Suspicious PATCH /api/settings Configuration Changes
    description: Detects unauthorized attempts to modify security-critical settings in 9router by identifying PATCH requests to /api/settings that include the requireLogin flag
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all 9router instances to a version beyond 0.5.2
      owner: IT Operations
      due: 24h
      evidence: Affected packages list indicates versions <= 0.5.2 are vulnerable
  hunt_leads:
    - lead: Search logs for PATCH requests to /api/settings followed by unauthorized access to /api/keys
      technique_id: T1068
      data_needed:
        - Web application access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC demonstrates that an attacker can access /api/keys after setting requireLogin to false
  mitigation_plan:
    - priority: immediate
      action: Block access to /api/settings from non-administrative IP addresses
      owner: Security Operations
      addresses: CVE-2026-56679
      evidence: Vulnerability allows global auth bypass
---

9router versions 0.5.2 and earlier contain a mass assignment vulnerability (CVE-2026-56679) within the `PATCH /api/settings` endpoint. The application fails to whitelist fields provided in the request body, allowing arbitrary fields to be written to the database. An authenticated attacker can specifically target the `requireLogin` field, setting it to `false`. Because the `dashboardGuard.js` middleware uses this setting to determine authentication status, disabling it effectively removes the authentication requirement for the entire application. This exposes sensitive endpoints like `/api/keys` and `/api/providers` to unauthenticated access, potentially leading to total system compromise when combined with known default credentials or previously obtained session tokens.

## Attack Chain

1. Attacker authenticates to the target 9router instance using a valid session or default credentials (e.g., password '123456').
2. Attacker crafts an HTTP PATCH request to the `/api/settings` endpoint.
3. Attacker includes `{"requireLogin": false}` in the JSON request body to trigger the mass assignment vulnerability.
4. The `PATCH` handler in `src/app/api/settings/route.js` accepts the input without validation and passes it to the `updateSettings` repository function.
5. The `updateSettings` function in `src/lib/db/repos/settingsRepo.js` performs a partial update, overwriting the stored `requireLogin` configuration in the database.
6. The `dashboardGuard.js` middleware observes the updated `requireLogin` setting and returns `true` for `isAuthenticated` checks for all subsequent requests.
7. Attacker performs unauthorized GET requests to sensitive endpoints such as `/api/keys` without providing credentials to exfiltrate API keys and configuration.

## Impact

Successful exploitation allows an authenticated user to achieve global authentication bypass. This results in the exposure of stored API keys, provider connection details, and dashboard administrative settings. The impact is elevated if the instance is exposed via a tunnel (`tunnelDashboardAccess` enabled), providing a remote vector for full system compromise.

## Recommendation

1. Upgrade 9router to a version beyond 0.5.2 immediately.
2. Audit `PATCH /api/settings` logs for requests containing unexpected keys, specifically focusing on `requireLogin`, `tunnelDashboardAccess`, and `authMode`.
3. Enforce re-authentication for all requests modifying security-critical settings by requiring current password validation at the application level.
4. Deploy network-level access controls to restrict access to the `/api` path until the patch is applied.

---
title: Privilege Escalation in Piccolo Admin via Session Token Exposure
slug: 2026-08-piccolo-admin-privesc
description: An improper access control implementation in the piccolo_admin /api/tables/sessions/ endpoint allows authenticated non-superuser admins to leak plaintext session tokens and perform privilege escalation to superuser status via CVE-2026-55485.
date: "2026-08-28T21:17:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:piccolo_admin:piccolo_admin:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-application
  - cve
vendors:
  - Piccolo
products:
  - piccolo_admin (<= 1.13.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated non-superuser admin can exploit this to retrieve plaintext session tokens... and gain unauthorized elevated privileges.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The sessions table stores live session tokens in plaintext... included in every GET response.
    confidence_band: high
cves:
  - id: CVE-2026-55485
    cvss: 8.8
references:
  - https://github.com/advisories/GHSA-2gh4-jmwq-rr8w
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55485
rules:
  - title: Detect CVE-2026-55485 Exploitation - Unauthorized GET to Sessions Endpoint
    description: Detects unauthorized access attempts to the sessions table via GET requests, which could indicate attempts to scrape session tokens.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1552.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade piccolo_admin to 1.14.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory confirms version <= 1.13.0 is vulnerable.
  hunt_leads:
    - lead: Search logs for GET /api/tables/sessions/ activity.
      technique_id: T1552.001
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this URI as the primary leakage point.
  mitigation_plan:
    - priority: immediate
      action: Patch piccolo_admin to 1.14.0 or later
      owner: IT Operations
      addresses: CVE-2026-55485
      evidence: Source provides specific fix recommendations for the validator.
---

The piccolo_admin package (up to and including version 1.13.0) contains a significant authorization vulnerability due to a flawed implementation of the `superuser_validators` helper function. This function utilizes a deny-list approach for protecting sensitive resources, restricting only `PUT`, `PATCH`, `DELETE`, and `POST` methods, while failing to block `GET` requests. Simultaneously, the `SessionsBase.token` field in the `piccolo_api` session authentication module is not marked as `secret=True`, resulting in the exposure of live session tokens in plaintext within `GET /api/tables/sessions/` responses. An attacker with standard (non-superuser) admin credentials can retrieve the session token for a superuser, replay that token to impersonate them, and subsequently modify their own user record to grant themselves permanent superuser privileges. This vulnerability, tracked as CVE-2026-55485, affects deployments that explicitly expose the `Sessions` table in the admin configuration, a pattern often used for session monitoring and management.

## Attack Chain

1. The attacker authenticates as a standard, non-superuser administrator (e.g., `admin=True`, `superuser=False`).
2. The attacker identifies that the `Sessions` table is exposed in the admin dashboard.
3. The attacker issues a `GET` request to `/api/tables/sessions/` to retrieve the entire contents of the sessions table.
4. The server returns a 200 OK response containing plaintext session tokens for all active users, including superusers.
5. The attacker extracts a superuser's session token from the JSON response.
6. The attacker uses the stolen superuser token in a new session cookie (`Cookie: id=...`) to authenticate requests to the admin API.
7. The attacker sends a `PATCH` request to `/api/tables/piccolo_user/<attacker_id>/` with the payload `{"superuser": true}`.
8. The server processes the request as the superuser, successfully promoting the attacker's account to superuser status.

## Impact

Successful exploitation results in full administrative takeover. An attacker can access all tables, modify user credentials, revoke existing sessions, and potentially plant payloads in exported data. The elevation is permanent, as the attacker effectively modifies the database record associated with their account.

## Recommendation

* Upgrade piccolo_admin and associated piccolo_api components immediately; identify the specific patched version from the vendor and apply it.
* Apply the recommended fix to `superuser_validators` by implementing an allow-list or a more restrictive `if not request.user.user.superuser: raise HTTPException` pattern to block all unauthorized access.
* Apply the defense-in-depth fix by setting `secret=True` on `SessionsBase.token` in `piccolo_api/session_auth/tables.py` to prevent plaintext leakage.
* Monitor web logs for `GET` requests to `/api/tables/sessions/` originated by users without `superuser` status.

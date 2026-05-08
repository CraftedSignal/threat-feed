---
title: Snipe-IT Privilege Escalation via API Permissions Assignment (CVE-2026-44832)
slug: 2024-01-03-snipeit-privesc
description: An authenticated user with limited 'users.edit' permissions can escalate their privileges to 'admin' in Snipe-IT versions before 8.4.1 by manipulating the permissions array in a PATCH request to the API, as tracked by CVE-2026-44832.
date: "2024-01-03T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - api
vendors:
  - Grokability
products:
  - Snipe-IT (< 8.4.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-hq28-crg7-95pr
rules:
  - title: Detect Snipe-IT Privilege Escalation Attempt via API (CVE-2026-44832)
    description: Detects CVE-2026-44832 exploitation — PATCH request to Snipe-IT API to elevate user privileges.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Snipe-IT User API Access
    description: Detects access to the Snipe-IT User API endpoints, which could indicate enumeration or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

Snipe-IT, a web-based IT asset management system, is susceptible to a privilege escalation vulnerability affecting versions prior to 8.4.1. An authenticated user possessing the `users.edit` permission can exploit this flaw to elevate their own privileges to that of an administrator. This is achieved by sending a specifically crafted PATCH request to the `/api/v1/users/{id}` endpoint, where the `permissions[admin]` parameter is set to '1'. The vulnerability, identified as CVE-2026-44832, arises due to insufficient validation on the server-side, allowing unauthorized modification of user permissions. The absence of proper input sanitization in the API controller enables users with limited privileges to assign administrative rights to themselves, undermining the system's security model.

## Attack Chain

1. An attacker authenticates to the Snipe-IT application with a user account that has the `users.edit` permission.
2. The attacker identifies the target user ID, typically their own user ID, which can be obtained from the user profile page or API.
3. The attacker crafts a PATCH request to `/api/v1/users/{id}`, replacing `{id}` with the target user's ID.
4. Within the PATCH request body, the attacker includes the parameter `permissions[admin]=1`.
5. The attacker sends the malicious PATCH request to the Snipe-IT server.
6. The Snipe-IT server, due to insufficient validation, accepts the request and updates the target user's permissions, granting them administrative privileges.
7. The attacker logs out and logs back in to the Snipe-IT application.
8. Upon logging back in, the attacker now possesses administrative privileges, allowing them to perform any action within the Snipe-IT system.

## Impact

Successful exploitation of this vulnerability allows an attacker with limited user privileges to gain full administrative control over the Snipe-IT system. This could lead to unauthorized access to sensitive data, modification or deletion of assets, creation of rogue administrator accounts, and complete compromise of the Snipe-IT installation. The vulnerability affects all Snipe-IT instances running versions prior to 8.4.1. The scope of the impact is limited to the Snipe-IT application itself.

## Recommendation

*   Upgrade Snipe-IT to version 8.4.1 or later to remediate CVE-2026-44832 as per the vendor's advisory.
*   Deploy the Sigma rule `Detect Snipe-IT Privilege Escalation Attempt via API` to monitor for suspicious PATCH requests to the `/api/v1/users/{id}` endpoint.
*   Enable web server access logging and review logs for unusual API requests targeting user permission modification.
*   Implement input validation and sanitization on all API endpoints, particularly those that handle user permissions.

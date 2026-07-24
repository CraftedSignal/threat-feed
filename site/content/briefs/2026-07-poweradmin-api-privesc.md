---
title: Poweradmin API Privilege Escalation via User-Update Endpoint
slug: 2026-07-poweradmin-api-privesc
description: A vulnerability in Poweradmin's REST API user-update endpoint allows a non-admin user with 'user_edit_others' permission to reset any user's password, including superusers, leading to full administrative account takeover by exploiting inconsistent authorization rules between the API and web UI.
date: "2026-07-24T21:58:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - api-vulnerability
  - account-takeover
vendors:
  - Poweradmin
products:
  - Poweradmin (>= 4.0.0, < 4.2.5)
  - Poweradmin (>= 4.3.0, < 4.3.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in Poweradmin's REST API user-update endpoint allows a non-admin user with 'user_edit_others' permission to reset any user's password, including superusers, leading to full administrative account takeover.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: resetting the administrator's password and logging in as the administrator achieves full control directly.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-h4hf-v6w5-897x
rules:
  - title: Detect Poweradmin API User Password Update Attempt for Superuser
    description: Detects attempts to update a user's password via Poweradmin's API, specifically targeting user ID 1 (often the superuser), which could indicate exploitation of GHSA-h4hf-v6w5-897x.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
---

A high-severity privilege escalation vulnerability (GHSA-h4hf-v6w5-897x) has been identified in Poweradmin, an open-source web-based management tool for PowerDNS. This flaw allows a non-administrative user with the `user_edit_others` permission to reset the password of any other user, including superuser accounts, through the REST API. This is due to a discrepancy where the API's user-update endpoint (`PUT/PATCH /api/v2/users/{id}` and its V1 equivalent) fails to enforce authorization checks present in the web interface. Specifically, the API lacks safeguards that prevent non-superusers from editing superuser accounts and from changing passwords without the `user_passwd_edit_others` permission. This vulnerability affects Poweradmin versions 4.0.0 through 4.2.4 and 4.3.0 through 4.3.3. Exploitation requires the REST API to be enabled and the existence of a delegated "user manager" role, which is common in many deployments for helpdesk or team lead functions. The result is a complete administrative account takeover with a single API request, allowing full control over DNS infrastructure.

## Attack Chain

1. An administrator configures Poweradmin with the REST API enabled and establishes a delegated "user manager" role that grants `user_edit_others` permission (ID 57) but not `user_is_ueberuser` (ID 53) or `user_passwd_edit_others` (ID 58).
2. An attacker gains access to credentials for a user assigned to this "user manager" role.
3. The attacker generates an API key associated with their "user manager" account within Poweradmin.
4. The attacker crafts an HTTP PUT or PATCH request targeting the Poweradmin API's user-update endpoint, specifying the superuser's account ID (commonly `1`) in the URL (e.g., `PUT /api/v2/users/1`).
5. The request body includes a JSON payload containing a new password for the targeted superuser account, such as `{"password":"NewAdminPass1!"}`.
6. Due to missing authorization logic in `lib/Domain/Service/ApiPermissionService.php::canEditUser()`, the API permits the non-superuser "user manager" to edit the superuser's account.
7. Subsequently, `lib/Domain/Service/UserManagementService.php::updateUser()` processes the request and writes the new password without verifying if the caller possesses `user_passwd_edit_others` permission.
8. The attacker then uses the newly set password to log into Poweradmin as the superuser, achieving full administrative control over the system and the underlying PowerDNS infrastructure.

## Impact

This broken access control and privilege escalation issue (CWE-285, CWE-266) allows any authenticated non-admin user with `user_edit_others` permission to gain full administrative control over affected Poweradmin installations. This directly impacts any Poweradmin deployment where the REST API is enabled and a delegated user management role exists. Upon successful exploitation, the attacker can reset the superuser's password, log in as the administrator, and subsequently control all zones, records, users, and settings within Poweradmin. This effectively grants control over the organization's DNS data managed by PowerDNS, posing a critical risk to network infrastructure and potentially enabling further attacks like traffic redirection or denial of service. The severity is high due to the complete administrative takeover achievable with a single over-the-network request from a low-privilege authenticated position.

## Recommendation

* Patch Poweradmin installations immediately to a fixed version (Poweradmin 4.2.5 or 4.3.4, or later) to resolve the vulnerability described in GHSA-h4hf-v6w5-897x.
* Deploy the `Detect Poweradmin API User Password Update Attempt for Superuser` Sigma rule to your SIEM to monitor for suspicious API calls targeting superuser accounts.
* Review web server access logs for PUT or PATCH requests to `/api/v[12]/users/1` by non-superuser accounts, especially those utilizing API keys, to identify potential exploitation attempts.
* If web server logs capture request bodies, examine them for JSON payloads containing a "password" field during API user update calls.

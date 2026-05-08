---
title: Open WebUI LDAP Empty Password Authentication Bypass
slug: 2024-01-24-open-webui-ldap-bypass
description: Open WebUI is vulnerable to an LDAP authentication bypass where the LDAP authentication endpoint does not validate that the submitted password is non-empty before performing a Simple Bind against the LDAP server, potentially granting attackers complete account access.
date: "2026-05-08T19:38:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - ldap
  - open-webui
products:
  - open-webui (<= 0.8.12)
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-2r4p-jpmg-48f4
rules:
  - title: Detect Open WebUI LDAP Authentication Bypass Attempt
    description: Detects CVE-2026-44551 exploitation — Monitors for POST requests to the `/api/v1/auths/ldap` endpoint with an empty password field, which indicates a potential authentication bypass attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
  - title: Detect Open WebUI LDAP Authentication Success with Empty Password
    description: Detects CVE-2026-44551 exploitation — Monitors for successful authentication events immediately following a POST request to the `/api/v1/auths/ldap` endpoint where the password was empty, indicating a successful authentication bypass.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI is vulnerable to an LDAP authentication bypass. The LDAP authentication endpoint does not validate that the submitted password is non-empty before performing a Simple Bind against the LDAP server. This vulnerability exists because the `LdapForm` Pydantic model accepts an empty string for the password field without any minimum length constraint. Subsequently, the `Connection.bind()` call succeeds on vulnerable LDAP servers, and the application issues a full session token for the target user. The issue affects the current main branch (commit `6fdd19bf1`) and likely all versions with LDAP authentication support. Exploitation requires that LDAP is enabled and the underlying LDAP server accepts unauthenticated simple binds with empty passwords, which is the default configuration for OpenLDAP and some Active Directory setups.

## Attack Chain

1. LDAP authentication is enabled on the Open WebUI instance (`ENABLE_LDAP=True`).
2. The attacker identifies a valid LDAP username.
3. The underlying LDAP server accepts unauthenticated simple binds (OpenLDAP default, some AD configs).
4. Attacker sends a POST request to `/api/v1/auths/ldap` with the target username and an empty password.
5. The application's DN bind succeeds, finding the target user via LDAP search.
6. The application attempts a user bind using the provided (empty) password.
7. The LDAP server returns success for the unauthenticated bind due to the empty password.
8. `authenticate_user_by_email` issues a full session token for the target user, granting complete account access.

## Impact

Successful exploitation allows a complete authentication bypass, enabling attackers to take over any LDAP user account without knowing the password, including admin accounts if they authenticate via LDAP. The vulnerability can be exploited with zero interaction from the victim and without rate limiting on the LDAP endpoint.

## Recommendation

*   Apply the mitigations recommended in GHSA-2r4p-jpmg-48f4 to prevent empty passwords from being used in LDAP authentication.
*   Deploy the Sigma rule "Detect Open WebUI LDAP Authentication Bypass Attempt" to monitor for POST requests to the `/api/v1/auths/ldap` endpoint with an empty password field, indicating a potential exploit attempt.
*   Ensure the LDAP server is configured to reject unauthenticated simple binds with empty passwords.
*   Monitor web server logs for POST requests to `/api/v1/auths/ldap` (webserver log source) and correlate with other authentication-related events.

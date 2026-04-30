---
title: Actual Privilege Escalation via change-password Endpoint on OpenID-Migrated Servers
slug: 2024-01-03-actual-privesc
description: Any authenticated user can escalate to ADMIN on Actual servers migrated from password authentication to OpenID Connect by exploiting a lack of authorization checks, orphaned password rows, and client-controlled login methods, leading to full administrative privileges.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - web-application
vendors:
  - Actual
products:
  - '@actual-app/sync-server'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-prp4-2f49-fcgp
rules:
  - title: Detect Password Change Attempts on OpenID-Only Servers
    description: Detects attempts to change the password on servers that should only be using OpenID Connect by monitoring requests to the /account/change-password endpoint when the server is configured for OpenID only.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Login Attempts with Client-Specified Password Method
    description: Detects login attempts where the client specifies the 'password' login method, potentially bypassing server-side authentication configurations.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1550
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Actual is vulnerable to a privilege escalation attack affecting servers migrated from password authentication to OpenID Connect. This vulnerability, identified as CVE-2026-33318, allows any authenticated user, regardless of their initial role (including the BASIC role), to gain full ADMIN access. The vulnerability stems from three weaknesses: a missing authorization check on the `/account/change-password` endpoint, the persistence of the inactive password `auth` row after migration, and the acceptance of a client-supplied `loginMethod` which bypasses the server's active auth configuration. This allows an attacker to overwrite the password hash for the admin account, authenticate, and gain complete control over the system. This affects multi-user servers running OpenID Connect that were previously configured with password authentication. Servers bootstrapped exclusively with OpenID are not affected. Versions prior to 26.4.0 of `@actual-app/sync-server` are vulnerable.

## Attack Chain

1.  Attacker obtains a valid session token for any user role (including BASIC) on a migrated Actual server.
2.  Attacker sends a POST request to `/account/change-password` with a new password, using the valid session token in the `X-Actual-Token` header and a JSON body containing the desired password.
3.  The server updates the password hash in the `auth` table for the inactive password authentication method, due to the missing authorization check.
4.  Attacker sends a POST request to `/account/login` with the `loginMethod` parameter set to "password" and the password set in the previous step.
5.  The server accepts the client-supplied `loginMethod` and authenticates the attacker as the anonymous admin account (username = ''), as this is the default user created during multiuser migration with ADMIN role.
6.  The server returns a new session token for the admin account.
7.  Attacker uses the admin token to access administrative functions on the server.
8.  Attacker can manage all users, access all budget files, modify file access controls, and change server configuration.

## Impact

Successful exploitation of this vulnerability grants an attacker full administrative privileges on the affected Actual server. This allows the attacker to manage all users, access all budget files regardless of ownership, modify file access controls, and change server configuration. The vulnerability affects multi-user servers running OpenID Connect that were previously configured with password authentication, meaning that a wide range of sensitive data and configurations are at risk. This can lead to significant data breaches, financial losses, and reputational damage.

## Recommendation

*   Apply the patch or upgrade to `@actual-app/sync-server` version 26.4.0 or later to remediate CVE-2026-33318.
*   Implement server-side checks to restrict access to the `/account/change-password` endpoint to password-authenticated sessions only, as recommended in the advisory.
*   Require current-password confirmation before accepting a new password via the `/account/change-password` endpoint.
*   Enforce the `active` status and remove client control over login method selection in the `getLoginMethod()` function.
*   As an immediate mitigation for existing deployments, administrators who have fully migrated to OpenID and do not need password auth can remove the orphaned password row using the SQL command: `DELETE FROM auth WHERE method = 'password';`.

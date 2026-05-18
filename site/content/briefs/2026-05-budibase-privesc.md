---
title: Budibase Builder-to-Admin Privilege Escalation via Unsecured onboardUsers Endpoint
slug: 2026-05-budibase-privesc
description: A privilege escalation vulnerability exists in Budibase's `onboardUsers` endpoint (CVE-2026-45716) allowing a builder-level user to create global admin accounts by bypassing the intended invite flow when SMTP is not configured, due to insufficient authorization checks and direct user creation with attacker-controlled roles.
date: "2026-05-18T17:44:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - budibase
vendors:
  - Budibase
products:
  - '@budibase/worker (< 3.38.1)'
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-c54j-xp92-wh28
  - CVE-2026-45716
rules:
  - title: Detect Budibase onboardUsers Endpoint Abuse
    description: Detects attempts to exploit the Budibase privilege escalation vulnerability (CVE-2026-45716) by monitoring POST requests to the `/api/global/users/onboard` endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Budibase Admin User Creation Without SMTP
    description: 'Detects the creation of new admin users in Budibase when SMTP is not configured by monitoring the http response for `created: true` and an admin role.'
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

A privilege escalation vulnerability (CVE-2026-45716) has been identified in Budibase versions prior to 3.38.1. The vulnerability resides in the `/api/global/users/onboard` endpoint, which is intended for onboarding users. However, when SMTP email configuration is absent (the default in self-hosted instances), the endpoint bypasses the typical admin-restricted invite flow. This allows a user with builder-level permissions to directly create new users with arbitrary roles, including global admin, using the `bulkCreate` function. The generated password for the new admin account is returned in the HTTP response. This vulnerability allows a low-privileged user to gain full administrative control over the Budibase platform.

## Attack Chain

1. Attacker authenticates to the Budibase instance with a builder-level account.
2. The attacker crafts a POST request to the `/api/global/users/onboard` endpoint.
3. The request body includes a JSON payload specifying a new user account with the `admin` role set to `true` for the global scope.
4. The `workspaceBuilderOrAdmin` middleware incorrectly authorizes the request due to the absence of a `workspaceId` parameter and the worker context.
5. The `onboardUsers` controller checks if SMTP is configured. Since it's not (default self-hosted setup), it skips the intended admin-only invitation path.
6. The controller directly creates a new user with the attacker-specified `admin` role using the `bulkCreate` function, without adequate permission validation.
7. The generated password for the new admin user is included in the HTTP response to the attacker.
8. The attacker uses the newly created admin account's credentials to log in and gain complete administrative access to the Budibase platform.

## Impact

This vulnerability allows any builder-level user to escalate their privileges to a global administrator on self-hosted Budibase instances that do not have SMTP configured. A successful attacker gains full platform compromise, including access to all apps, data sources, user management capabilities, and the ability to delete apps or modify platform configurations. The exposure of the generated password in the HTTP response provides immediate access to the new admin account, compounding the severity. This vulnerability affects a significant portion of self-hosted Budibase instances due to the default configuration without SMTP.

## Recommendation

*   Upgrade Budibase to version 3.38.1 or later to patch CVE-2026-45716.
*   Implement the recommended fix by modifying `/packages/worker/src/api/routes/global/users.ts` to move the `onboardUsers` route to `adminRoutes` as described in the advisory.
*   Deploy the Sigma rule "Detect Budibase onboardUsers Endpoint Abuse" to identify exploitation attempts.
*   Review existing user accounts and roles, focusing on builder-level accounts, for any signs of unauthorized privilege escalation using the steps outlined in the Attack Chain.
*   Configure SMTP to prevent the vulnerable code path from being executed; however, this does not address the underlying authorization issue.

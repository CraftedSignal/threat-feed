---
title: Open WebUI LDAP/OAuth Race Condition Allows Multiple Admin Accounts (CVE-2026-45675)
slug: 2026-05-open-webui-admin-race
description: Open WebUI versions 0.8.12 and earlier are vulnerable to a time-of-check-time-of-use (TOCTOU) race condition in the LDAP and OAuth authentication flows, allowing multiple concurrent requests on a fresh instance to bypass the first-user admin role assignment and resulting in multiple admin accounts (CVE-2026-45675).
date: "2026-05-14T20:30:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - time-of-check-time-of-use
  - race-condition
  - cve-2026-45675
  - cloud
vendors:
  - Open Web UI
products:
  - open-webui (<= 0.8.12)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://github.com/advisories/GHSA-h3ww-q6xx-w7x3
  - https://github.com/open-webui/open-webui/pull/23626
  - https://github.com/open-webui/open-webui/commit/96a0b3239b1aadb23fc359bf10849c9ba12fd6ec
rules:
  - title: Detect Open WebUI Multiple Admin Account Creation
    description: Detects potential exploitation of CVE-2026-45675 in Open WebUI where multiple admin accounts are created within a short timeframe after initial deployment via LDAP/OAuth.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
      - s0001
    techniques:
      - T1134
      - T1134.001
    data_sources:
      - webserver
  - title: Detect Open WebUI OAuth Admin Role Assignment
    description: Detects OAuth requests to the /api/auth/callback endpoint with a successful 200 response and an empty user list, which indicates a potential exploitation of CVE-2026-45675 if followed by multiple admin role assignments
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
      - s0001
    techniques:
      - T1134
      - T1134.001
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI versions 0.8.12 and earlier are vulnerable to a time-of-check-time-of-use (TOCTOU) race condition in the LDAP and OAuth authentication flows. This vulnerability, identified as CVE-2026-45675, occurs because the LDAP and OAuth authentication code paths determine the admin role *before* inserting the user into the database. This creates a race condition where multiple concurrent requests to a new Open WebUI instance can all observe an empty user database and, consequently, all be assigned the admin role. The vulnerability was resolved in version 0.9.0 with a change to assign a default role upon user creation, then upgrading that role to admin only if the new user is the sole user in the database. This impacts deployments utilizing LDAP or OAuth for authentication.

## Attack Chain

1. Deploy Open WebUI version 0.8.12 or earlier on a fresh instance with either LDAP or OAuth enabled for authentication.
2. An attacker initiates multiple concurrent authentication requests from different user accounts.
3. Each authentication request reaches the `has_users()` or `get_num_users()` function in `auths.py` or `oauth.py` respectively.
4. Due to the concurrent nature of the requests, multiple requests simultaneously observe an empty user database.
5. The system incorrectly assigns the `admin` role to each of these concurrent requests based on the flawed check.
6. `Auths.insert_new_auth` inserts multiple users, all with the `admin` role.
7. The attackers gain unauthorized administrative access to the Open WebUI instance.
8. Attackers can then access sensitive user data, system configurations, API keys, and connected LLM backends.

## Impact

Successful exploitation of CVE-2026-45675 allows any LDAP or OAuth user who authenticates concurrently with the initial legitimate administrator to escalate their privileges to full admin. This grants unauthorized access to all user data, system configurations, API keys, and connected LLM backends. The number of affected installations depends on the adoption rate of Open WebUI and the prevalence of LDAP/OAuth usage, but this vulnerability poses a significant risk to data confidentiality and integrity for affected deployments. The fix was released in v0.9.0.

## Recommendation

*   Upgrade Open WebUI to version 0.9.0 or later to remediate CVE-2026-45675.
*   Deploy the Sigma rule "Detect Open WebUI Multiple Admin Account Creation" to monitor for potential exploitation attempts (rule below).
*   If upgrading is not immediately feasible, consider temporarily disabling LDAP/OAuth authentication and relying on local accounts.

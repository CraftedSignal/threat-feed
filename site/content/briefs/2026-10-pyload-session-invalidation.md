---
title: pyLoad Session Invalidation Failure After Privilege Revocation
slug: 2026-10-pyload-session-invalidation
description: An improper implementation of the set_user_permission API endpoint in pyLoad allows users to retain elevated permissions for up to 31 days after an administrator has explicitly revoked their access.
date: "2026-10-09T21:27:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - persistence
  - api-security
vendors:
  - pyLoad
products:
  - pyLoad (all versions prior to fix)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The demoted user retains their elevated permission bits on every subsequent WebUI page load and every subsequent /api/<func> call made with that cookie.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit use of the RPC set_user_permission endpoint to identify potentially stale sessions
      owner: SOC
      due: 24h
      evidence: Source explicitly identifies API endpoint as the vector for privilege modification
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the patched version of pyLoad when available
      owner: IT Operations
      addresses: Missing session invalidation logic
      evidence: Suggested fix provided by advisory
---

pyLoad contains a security flaw where the `Api.set_user_permission` method fails to invalidate active user sessions when an administrator modifies a user's role or permissions via the RPC interface. The vulnerability exists because pyLoad caches authorization data (roles and permissions) within the Flask session cookie during the initial login event and does not perform re-validation against the backend database for subsequent requests. 

While the `update_users()` route in the WebUI correctly includes a call to `clear_all_user_sessions(name)`, the public `/api/<func>` RPC dispatcher calls `Api.set_user_permission` directly, bypassing this crucial invalidation step. Consequently, a user whose privileges have been demoted retains their original session cookie, which continues to grant access to restricted endpoints for the duration of the 31-day session lifetime, unless the user voluntarily terminates the session. This vulnerability poses a significant risk to organizations relying on pyLoad's RPC interface for automated user management.

## Attack Chain

1. Victim authenticates to pyLoad via the WebUI, obtaining a valid Flask session cookie containing cached role and permission bits.
2. Victim utilizes their current, elevated permissions to access a sensitive resource, such as `/api/get_userdir`.
3. Administrator identifies a need to demote the victim and executes a `POST /api/set_user_permission` request via the public RPC interface.
4. The `Api.set_user_permission` function successfully updates the victim's permission and role bits in the backend database.
5. The API call returns successfully, but the function fails to trigger a session invalidation routine for the target user.
6. The victim continues to use their original session cookie to access the application.
7. The application's `apikey_auth` logic rebuilds the user context directly from the stale session cookie fields.
8. The application performs authorization checks against the stale, elevated permission bits, permitting the victim to continue unauthorized activity.

## Impact

The impact of this vulnerability is unauthorized access to privileged features by users who have been demoted by an administrator. This access can persist for up to 31 days, the default session lifetime in pyLoad. This may lead to unauthorized data access, persistence of configuration changes, or misuse of administrative functions if the demoted user retains access to management APIs. The vulnerability affects all deployments of pyLoad that utilize the RPC interface for user management and have not applied the necessary session invalidation patches.

## Recommendation

1. Update pyLoad to a patched version that explicitly invokes `clear_all_user_sessions(name)` within the `Api.set_user_permission` method.
2. Until a patch is applied, audit the use of the `/api/set_user_permission` endpoint and manually terminate user sessions via the WebUI "Manage Users" interface after any manual RPC privilege changes.
3. Implement network-level monitoring to identify unauthorized calls to administrative API endpoints by non-privileged accounts, focusing on the `/api/` URI prefix.
4. Review access logs for instances where sensitive API endpoints are accessed by user accounts that have recently undergone privilege changes.

---
title: Arcane Admin Account Takeover via Improper Authorization
slug: 2026-10-arcane-admin-takeover
description: An authorization flaw in the Arcane user management API allows users with the 'users:update' permission to overwrite administrative credentials and hijack global administrator accounts.
date: "2026-10-16T22:28:32Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:arcane:arcane:*:*:*:*:*:*:*:*
vendors:
  - Arcane
products:
  - Arcane (<= 2.5.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Arcane backend implementation of the UpdateUser function lacks an authorization check to verify if the caller has sufficient privileges relative to the target user.
    confidence_band: high
cves:
  - id: CVE-2026-96627
    cvss: 8.8
references:
  - https://github.com/advisories/GHSA-pw5q-rjx4-7f7p
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96627
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Arcane backend to v2.6.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source documentation for CVE-2026-96627
  mitigation_plan:
    - priority: immediate
      action: Revoke users:update permission from non-admin roles
      owner: Security Engineering
      addresses: CVE-2026-96627
      evidence: The permission users:update allows exploitation regardless of account hierarchy
---

Arcane versions 2.5.0 and earlier contain a critical authorization vulnerability within the `UpdateUser` API handler. The application permits users assigned the delegated `users:update` permission to update the `PasswordHash` of any target user, including global administrators. The vulnerability arises because the backend logic in `backend/api/handlers/users.go` and `user_service.go` lacks a privilege-hierarchy check, performing an unconditional `tx.Save` operation on the user model provided in the request body. While Arcane implements `RequireGlobalAdmin` guards for administrative tasks like role creation, the user management endpoint fails to enforce the separation between standard account profile maintenance and privileged administrative actions. This allows an attacker to reset the administrator's password, authenticate as the admin, and achieve full control over the application environment.

## Attack Chain

1. An administrator creates a custom role for a user, granting them the `users:update` permission for legitimate profile management tasks.
2. The attacker, possessing this `users:update` permission, authenticates to the application using their own account.
3. The attacker identifies the `adminId` for the global administrator account.
4. The attacker sends a `PUT` request to `/users/{adminId}` with a JSON payload containing a new `password` field (e.g., `{"password":"attacker123"}`).
5. The server validates the attacker has the `users:update` permission but fails to verify if the caller is authorized to modify an administrator's account.
6. The `UpdateUser` handler updates the administrator's `PasswordHash` in the database to the attacker's chosen value.
7. The attacker authenticates to the application via `POST /auth/login` using the compromised administrative credentials.
8. The attacker obtains an administrative session and takes full control of the platform.

## Impact

The vulnerability results in complete administrative account takeover, enabling unauthorized access to application data, configuration settings, and user management capabilities. This impact is rated with high confidentiality, integrity, and availability loss. Any user with the delegated `users:update` role can effectively compromise the entire instance.

## Recommendation

1. Upgrade the Arcane backend (github.com/getarcaneapp/arcane/backend/v2) to version 2.6.0 or later immediately to patch CVE-2026-96627.
2. Conduct an audit of all custom roles and user permissions in the application to ensure that the `users:update` permission is not granted to untrusted accounts.
3. Monitor web server logs for suspicious `PUT` requests to the `/users/` endpoint directed at known administrator accounts.
4. If patching is not immediately feasible, remove the `users:update` permission from any non-administrative roles to prevent exploitation.

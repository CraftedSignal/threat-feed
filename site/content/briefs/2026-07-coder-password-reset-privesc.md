---
title: Coder User-Admin Role Can Reset Owner Account Password (CVE-2026-55077)
slug: 2026-07-coder-password-reset-privesc
description: A critical vulnerability, CVE-2026-55077, in the Coder platform allowed a user with the `user-admin` role to reset the password of an `owner` account without needing the current password via the `PUT /api/v2/users/{user}/password` endpoint, leading to privilege escalation and full deployment control.
date: "2026-07-06T20:56:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-vulnerability
  - api-vulnerability
  - coder
vendors:
  - Coder
products:
  - Coder (>= 2.34.0, < 2.34.2)
  - Coder (>= 2.33.0, < 2.33.8)
  - Coder (>= 2.30.0, < 2.32.7)
  - Coder (< 2.29.17)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A `user-admin` could reset any owner's password without knowing it, authenticate as that owner and gain full deployment control.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-29xf-69gq-m9jx
  - CVE-2026-55077
---

A significant privilege escalation vulnerability (CVE-2026-55077) has been identified in the Coder platform, impacting several versions including >= 2.34.0, < 2.34.2; >= 2.33.0, < 2.33.8; >= 2.30.0, < 2.32.7; and < 2.29.17. This flaw permits an attacker holding the `user-admin` role to reset the password of any `owner` account without requiring the current password. The vulnerability stems from an insufficient authorization check on the `PUT /api/v2/users/{user}/password` endpoint, which only verified `ActionUpdatePersonal` permissions. This oversight allows a less privileged `user-admin` to effectively seize full administrative control over the Coder deployment, including managing templates, workspaces, licensing, and organization settings. While exploitation requires an existing `user-admin` role, organizations granting this role to less trusted operators are at direct risk.

## Attack Chain

1.  **Initial Access as `user-admin`**: An attacker obtains or is assigned the `user-admin` role within a vulnerable Coder deployment.
2.  **Target Owner Account**: The attacker identifies the user ID of an account holding the `owner` role.
3.  **API Password Reset Request**: The attacker crafts and sends a `PUT` request to the `/api/v2/users/{owner_user_id}/password` endpoint, specifying a new password for the owner account.
4.  **Unauthorized Password Change**: Due to the vulnerability, the Coder application processes the request, resetting the `owner` account's password without validating the requesting user's authorization to modify an owner's credentials or requiring the old password.
5.  **Owner Account Impersonation**: The attacker authenticates to the Coder platform using the compromised `owner` account with the newly set password.
6.  **Full Deployment Control**: The attacker, now operating as the `owner`, gains complete administrative control over the Coder deployment, including access to all templates, workspaces, licensing, and organization settings, effectively escalating privileges.

## Impact

Successful exploitation of CVE-2026-55077 allows a `user-admin` to elevate their privileges to that of an `owner`. This grants the attacker full control over the Coder deployment, encompassing the ability to manage all templates, workspaces, licensing configurations, and organizational settings. Furthermore, the attacker can self-assign the `owner` role if needed. The primary risk is to organizations that delegate the `user-admin` role to less trusted personnel, as this vulnerability bypasses intended role-based access controls, potentially leading to unauthorized data access, system disruption, or further compromise of integrated systems.

## Recommendation

*   **Patch CVE-2026-55077**: Immediately upgrade affected Coder instances to patched versions v2.34.2, v2.33.8, v2.32.7, or v2.29.17 as appropriate for your release line to remediate CVE-2026-55077.
*   **Implement Workaround**: Restrict the `user-admin` role to only trusted administrators until the Coder platform can be fully upgraded.

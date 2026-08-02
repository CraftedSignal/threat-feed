---
title: Authentication Bypass and Privilege Escalation in Vikunja API
slug: 2026-08-vikunja-auth-bypass
description: Vikunja versions 0.22.0 through 2.3.0 contain an authentication bypass vulnerability allowing attackers to impersonate users and manage their API tokens via manipulated link-share JWTs.
date: "2026-08-02T13:36:25Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Vikunja
products:
  - Vikunja (0.22.0 through 2.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The attacker can use a link-share JWT to impersonate a user if the link-share ID matches the target user's numeric ID.
    confidence_band: high
cves:
  - id: CVE-2026-68581
    cvss: 8.1
---

Vikunja versions 0.22.0 through 2.3.0 are affected by a flaw in API token management where the application fails to validate the principal type during ID resolution. The vulnerability stems from the use of a generic web.Auth.GetID() interface that treats user IDs and link-share IDs as identical numeric sequences. An authenticated attacker can identify a target user's numeric ID and repeatedly create link shares on a project they control until the link-share identifier increments to match the target's user ID. By generating a JWT for this specific link share, the attacker can successfully impersonate the target user when accessing the /api/v1/tokens endpoints. This allows the attacker to list, delete, or create new API tokens with arbitrary scopes under the victim's identity. This vulnerability was addressed in Vikunja version 2.4.0.

## Attack Chain

1. Attacker authenticates to the Vikunja instance with a standard low-privilege account.
2. Attacker performs an authenticated user search to enumerate and capture the target's numeric user ID.
3. Attacker accesses a project they have write access to and creates multiple link shares.
4. Attacker monitors the link-share incrementing sequence until the ID matches the target user's numeric ID.
5. Attacker generates a JWT associated with the specific malicious link share.
6. Attacker sends an HTTP request to the /api/v1/tokens endpoint using the link-share JWT.
7. The application incorrectly resolves the JWT principal as the target user.
8. Attacker successfully creates or deletes API tokens on behalf of the target user to achieve persistence or exfiltration.

## Impact

The vulnerability allows for complete account takeover of API token management. An attacker can create new API tokens with escalated permissions, effectively gaining long-term programmatic access to the victim's data, tasks, and integrations. This vulnerability impacts any organization using Vikunja for sensitive project management or internal task tracking.

## Recommendation

1. Upgrade all instances of Vikunja to version 2.4.0 or higher immediately to apply the fix for CVE-2026-68581.
2. Review application logs for unusual spikes in link-share creation activity, which may indicate an attacker attempting to brute-force the numeric ID sequence.
3. Audit existing API tokens for any unexpected tokens created by users, particularly those with administrative or broad read/write scopes.

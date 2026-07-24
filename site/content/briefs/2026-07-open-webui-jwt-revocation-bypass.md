---
title: 'Open WebUI: Realtime Endpoints Fail to Revoke JWTs'
slug: 2026-07-open-webui-jwt-revocation-bypass
description: Open WebUI versions from 0.9.0 to before 0.10.0, when configured with Redis, fail to correctly enforce JWT revocation for realtime authentication endpoints such as Socket.IO and terminal websockets, allowing attackers to maintain access to real-time features with stolen, revoked JWTs.
date: "2026-07-24T17:01:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openwebui:open_webui:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - jwt
  - authentication
  - webui
  - realtime
  - bypass
products:
  - Open WebUI (>= 0.9.0, < 0.10.0)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: A JWT revoked by sign-out or back-channel logout therefore continues to authenticate new realtime connections, even though the same token is rejected on HTTP.
    confidence_band: high
cves:
  - id: CVE-2026-59219
    cvss: 7.1
    epss: 0.00259
references:
  - https://github.com/advisories/GHSA-855v-hq7w-jmjw
---

Open WebUI versions between 0.9.0 and 0.10.0 (exclusive), specifically when configured to use Redis for token management, contain a critical vulnerability identified as CVE-2026-59219. This flaw prevents proper JWT revocation enforcement on the application's realtime communication channels, including Socket.IO connections and terminal websockets. While the HTTP REST API correctly rejects tokens that have been invalidated by user sign-out or OIDC back-channel logout, the realtime endpoints only verify token signature and expiry, neglecting to check the revocation status in Redis. This oversight allows an attacker who has compromised a user's JWT to retain unauthorized access to sensitive realtime functionalities, such as collaborative notes, chat messages, and potentially terminal sessions, even after the legitimate user has taken steps to revoke the token, thereby bypassing a crucial security measure designed to mitigate the impact of stolen credentials. The vulnerability affects installations configured with Redis for JWT revocation.

## Attack Chain

1. An attacker compromises a legitimate user's JSON Web Token (JWT) for Open WebUI.
2. The legitimate user signs out from Open WebUI, or their Identity Provider initiates an OIDC back-channel logout.
3. Open WebUI's Redis instance correctly records the compromised JWT as revoked and updates the user's `revoked_at` timestamp.
4. The attacker attempts to use the revoked JWT to access Open WebUI's HTTP REST API endpoints; these attempts are correctly denied with a 401 Unauthorized error due to proper revocation checks.
5. The attacker then initiates a new connection to one of Open WebUI's realtime endpoints, such as a Socket.IO connection (for chat, collaborative notes) or a terminal websocket.
6. The attacker presents the previously revoked JWT to the realtime endpoint for authentication.
7. Due to CVE-2026-59219, the realtime endpoint's authentication logic only performs checks for token signature validity and expiry, but critically fails to consult the Redis revocation status.
8. The attacker successfully authenticates to the realtime service, gaining unauthorized access to and control over features like reading channel messages, participating in collaborative notes, and accessing terminal sessions as the legitimate user, despite the token having been officially revoked.

## Impact

The successful exploitation of CVE-2026-59219 allows an attacker to maintain unauthorized, persistent access to an Open WebUI user's realtime functionalities, even after the legitimate user has performed a sign-out or an OIDC back-channel logout has been processed. This bypasses the intended remediation for compromised tokens. Attackers can leverage this persistent access to join user, channel, and note rooms, receive realtime channel messages and collaborative note updates, drive socket-level collaboration, and pass authentication for terminal websockets. This can lead to sensitive information disclosure, unauthorized data manipulation in collaborative environments, and potential remote execution capabilities if terminal servers are configured, effectively allowing the attacker to impersonate the victim in realtime interactions.

## Recommendation

* Patch CVE-2026-59219 immediately by upgrading all affected Open WebUI installations to version 0.10.0 or later.
* Ensure that Open WebUI instances configured with Redis are updated, as the vulnerability only manifests in this configuration.
* Review network logs for suspicious long-lived connections to Open WebUI's Socket.IO or websocket endpoints from IP addresses not associated with legitimate users, which could indicate a post-revocation bypass attempt.

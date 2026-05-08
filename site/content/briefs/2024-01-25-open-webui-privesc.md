---
title: Open WebUI Stale Admin Role Enables Post-Demotion Cross-User Note Access
slug: 2024-01-25-open-webui-privesc
description: Open WebUI is vulnerable to privilege escalation; when a user connects via Socket.IO, their role is stored in an in-memory session pool, and administrative changes do not invalidate this session, allowing unauthorized access and modification of other users' notes after role revocation.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - credential-access
  - cloud
vendors:
  - open-webui
products:
  - open-webui (<= 0.8.12)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Media
references:
  - https://github.com/advisories/GHSA-45m8-cpm2-3v65
rules:
  - title: Detect Open WebUI Note Access Attempt with Stale Admin Session
    description: Detects potential attempts to access or modify notes in Open WebUI by users who may have had their admin privileges revoked, leveraging stale sessions.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect Open WebUI Admin Role Update via API
    description: Detects modifications to user roles via the Open WebUI API, which may precede exploitation of stale session vulnerabilities.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI, a web interface for large language models, is susceptible to a privilege escalation vulnerability stemming from how it manages user sessions via Socket.IO. Specifically, when a user establishes a connection, their role (e.g., 'admin') is cached in an in-memory `SESSION_POOL`. Crucially, subsequent administrative actions like role revocation or user deletion, performed through HTTP endpoints, do not invalidate existing Socket.IO sessions. As a result, a user who has been demoted or deleted can retain their previous admin privileges within the active Socket.IO session indefinitely, so long as they maintain the connection via heartbeats. This vulnerability impacts current main branch (commit `6fdd19bf1`) and likely all versions with the collaborative document (Yjs) Socket.IO handlers.

## Attack Chain

1. User B authenticates as an administrator and establishes a Socket.IO connection, which stores their `role` as `admin` in the `SESSION_POOL`.
2. Administrator A demotes User B to a regular user via the `POST /api/v1/users/{B_id}/update` endpoint, modifying the user's role in the database.
3. The Socket.IO session remains active, and User B's `SESSION_POOL` entry retains the stale `admin` role.
4. User B's client continues sending `heartbeat` events to maintain the Socket.IO connection, refreshing only the `last_seen_at` timestamp in the `SESSION_POOL`.
5. User B sends a `ydoc:document:join` event with the `document_id` of a note belonging to another user (e.g., `note:<victim_note_id>`).
6. The server-side handler at `socket/main.py:538` checks the cached role from the `SESSION_POOL`, incorrectly granting access due to the stale `admin` role.
7. User B now gains read access to the victim's note, receives the full document state, and gets live updates.
8. User B sends a `ydoc:document:update` event, and the handler at `socket/main.py:611` bypasses authorization using the cached role, allowing User B to modify the victim's note's content.

## Impact

Successful exploitation of this vulnerability allows unauthorized read and write access to any user's notes. This occurs even after admin privileges have been legitimately revoked. The attacker only needs to maintain an active Socket.IO connection established while they had administrative rights, which is trivial as heartbeats keep the session alive indefinitely. This grants a false sense of security to administrators who revoke privileges, as the revocation only affects HTTP access but not real-time collaborative access.

## Recommendation

*   Apply available patches or upgrade Open WebUI to a version that addresses CVE-2026-44553.
*   Implement a mechanism to invalidate Socket.IO sessions upon user role changes or deletions to prevent the use of stale privileges. Specifically, invalidate or update `SESSION_POOL` entries when user roles are modified via the `/api/v1/users/{B_id}/update` endpoint.
*   Deploy the Sigma rule "Detect Open WebUI Note Access Attempt with Stale Admin Session" to identify potential attempts to access notes using stale admin sessions.
*   Review and audit the implementation of the Socket.IO session management, particularly the `connect` and `heartbeat` handlers in `backend/open_webui/socket/main.py`, to ensure proper role validation.

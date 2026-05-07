---
title: Aegra Cross-Tenant IDOR in Thread Run Creation
slug: 2024-01-aegra-idor
description: Aegra versions 0.9.0 through 0.9.6 are vulnerable to a cross-tenant IDOR, enabling authenticated users to execute graph runs against other users' threads, read checkpoint states, inject messages, and conceal their actions due to missing user ID validation on run creation endpoints; patched in version 0.9.7.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - privilege-escalation
  - credential-access
  - defense-evasion
vendors:
  - Aegra
products:
  - aegra-api
  - aegra
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1212
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1212
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1212
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-m98r-6667-4wq7
  - https://github.com/aegra/aegra/issues/336
  - https://github.com/aegra/aegra/pull/337
  - https://github.com/aegra/aegra/releases/tag/v0.9.7
rules:
  - title: Detect Aegra Cross-Tenant IDOR Attempt
    description: Detects attempts to exploit a cross-tenant IDOR vulnerability in Aegra by monitoring POST requests to the /threads/{thread_id}/runs endpoints.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
  - title: Detect Aegra Thread ID Access in Web Logs
    description: Detects access to Aegra thread IDs in web server logs, which could be an initial step towards exploiting the IDOR vulnerability.
    platform: sigma
    severity: informational
    tactics:
      - privilege_escalation
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A cross-tenant IDOR vulnerability affects Aegra deployments running versions 0.9.0 through 0.9.6 where multiple authenticated users share an instance. An authenticated user (User A) can exploit this by leveraging another user's `thread_id` (User B) to perform unauthorized actions. User A can execute graph runs against User B's thread, read User B's full checkpoint state, inject arbitrary messages into User B's conversation history, and hide their activity from User B's `GET /threads/{thread_id}/runs` listing. The issue arises because the run carries A's `user_id`, not B's. The streaming variant of the run creation endpoints exacerbates the vulnerability by returning the entire prior `messages` array immediately upon connection, without requiring graph execution. This vulnerability was discovered by @JoJoTheBizarre and resolved in version 0.9.7.

## Attack Chain

1. User A authenticates to the Aegra application.
2. User A obtains User B's `thread_id` through frontend URLs, server logs, observability traces, or shared links.
3. User A crafts a `POST` request to `/threads/{thread_id}/runs`, `/threads/{thread_id}/runs/stream`, or `/threads/{thread_id}/runs/wait`, replacing `{thread_id}` with User B's `thread_id`.
4. The Aegra application fails to validate that User A owns the target `thread_id` due to a missing `user_id` filter at the SQL layer.
5. The request executes a graph run within User B's thread context, using User A's credentials.
6. User A reads User B's full checkpoint state via the resulting run's `output` field (or via SSE events in the streaming variant).
7. User A injects arbitrary messages into User B's conversation history, which are then persisted in User B's checkpoint.
8. User A's actions are hidden from User B's thread run listing because the run is associated with User A's `user_id`.

## Impact

Successful exploitation allows an attacker to execute arbitrary code within another user's context, potentially leading to data exfiltration, modification of user data, and disruption of service. With multiple authenticated users on a shared instance, any user can read the full checkpoint state or inject arbitrary messages into another user's conversation history. If streaming is enabled the attacker can read the full conversation history without further steps.

## Recommendation

*   Upgrade Aegra deployments to version 0.9.7 or later to address the vulnerability as per the patch notes.
*   If upgrading is not immediately feasible, implement the workaround by registering an `@auth.on("threads", "create_run")` handler that explicitly verifies thread ownership against the authenticated identity before allowing the operation, as detailed in the workaround section.
*   Monitor web server logs for suspicious `POST` requests to the affected endpoints (`/threads/{thread_id}/runs`, `/threads/{thread_id}/runs/stream`, `/threads/{thread_id}/runs/wait`) originating from unexpected IP addresses using the Sigma rule "Detect Aegra Cross-Tenant IDOR Attempt".

---
title: Authentication Bypass in APITable InternalUserController
slug: 2026-08-apitable-auth-bypass
description: APITable versions up to 1.13.0-beta.1 contain an authentication bypass vulnerability in the InternalUserController, allowing unauthenticated attackers to permanently delete user accounts currently in a cooling-off period.
date: "2026-08-27T19:10:05Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - authentication-bypass
  - web-application-vulnerability
  - data-destruction
vendors:
  - APITable
products:
  - APITable
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The nginx gateway shipped with the product proxies every /api request to the backend server, so both endpoints are reachable by any unauthenticated client that can reach the gateway.
    confidence_band: high
cves:
  - id: CVE-2026-80208
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80208
rules:
  - title: Detect Exploitation of CVE-2026-80208 - Unauthorized Access to InternalUserController
    description: Detects unauthenticated access attempts to internal account management endpoints in APITable
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Implement web server access control list (ACL) rules to restrict /api/v1/internal/ access
      owner: IT Operations
      due: 24h
      evidence: Endpoints are reachable by any unauthenticated client that can reach the gateway.
  mitigation_plan:
    - priority: immediate
      action: Upgrade APITable to a patched version beyond 1.13.0-beta.1
      owner: IT Operations
      addresses: CVE-2026-80208
      evidence: NVD vulnerability notice
---

APITable versions up to and including 1.13.0-beta.1 contain an authentication bypass vulnerability in the `InternalUserController` class. The endpoints `getUserHistories` and `closePausedUserAccount` are incorrectly annotated with `requiredLogin = false`. The application's `ResourceInterceptor` honors this annotation by skipping session or API key validation for these routes. Because the product's bundled nginx gateway proxies all `/api` requests to the backend, these sensitive administrative functions are exposed to any unauthenticated client with network access to the gateway. An attacker can exploit this to enumerate accounts awaiting permanent deletion and finalize the removal process, thereby bypassing the 30-day account recovery cooling-off period. This leads to irreversible data loss for targeted users.

## Attack Chain

1. Attacker performs network reconnaissance to identify an APITable instance reachable via HTTP/HTTPS.
2. Attacker probes the `/api/v1/internal/` path to determine if the `InternalUserController` endpoints are exposed without authentication.
3. Attacker sends a POST request to `/api/v1/internal/getUserHistories` to retrieve a list of all user accounts currently in a 30-day cooling-off (deleted/paused) state.
4. Attacker parses the response to extract valid `userId` values for the identified target accounts.
5. Attacker iterates through the collected `userId` values.
6. Attacker sends a POST request to `/api/v1/internal/users/{userId}/close` for each identified account.
7. The backend processes the closure, clearing PII, canceling subscriptions, and deleting OAuth bindings.
8. Account recovery is successfully prevented, resulting in permanent data destruction for the targeted user.

## Impact

Successful exploitation results in the permanent loss of user accounts that are otherwise protected by a 30-day recovery window. This vulnerability impacts the integrity and availability of user data within the APITable platform. While the scope of impact depends on the number of accounts currently in the cooling-off period, unauthorized access to administrative internal APIs constitutes a critical breach of the platform's security boundary.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Implement monitoring on web server logs for HTTP POST requests to `/api/v1/internal/` originating from untrusted or non-administrative source IPs.
- Patch APITable to a version beyond 1.13.0-beta.1 that corrects the `requiredLogin` annotation for the `InternalUserController`.
- Restrict network access to the `/api/v1/internal/` path at the nginx gateway or firewall level to ensure only authorized management IPs can access these administrative endpoints.

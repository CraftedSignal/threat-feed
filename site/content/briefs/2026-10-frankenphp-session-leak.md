---
title: FrankenPHP Cross-Request Session ID Leak in Worker Mode
slug: 2026-10-frankenphp-session-leak
description: A build-time dependency issue in FrankenPHP causes cross-user session ID leakage when the PHP session extension is loaded as a shared module in worker mode.
date: "2026-10-15T22:24:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dunglas:frankenphp:*:*:*:*:*:*:*:*
tags:
  - web-application
  - session-management
  - vulnerability
vendors:
  - Dunglas
products:
  - FrankenPHP (<= 1.12.4)
cves:
  - id: CVE-2026-82416
    cvss: 7.7
    epss: 0.00227
references:
  - https://github.com/advisories/GHSA-v3ph-cgqh-r8p5
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82416
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Audit server environments for PHP session extension loading method (shared vs static)
      owner: IT Operations
      due: 48h
      evidence: Source documentation on build-time dependency
  mitigation_plan:
    - priority: immediate
      action: Switch to official FrankenPHP static binaries or Docker images
      owner: IT Operations
      addresses: CVE-2026-82416
      evidence: Source workaround recommendation
---

FrankenPHP is susceptible to a cross-user session ID leakage vulnerability when operating in worker mode. The root cause is a build-time configuration discrepancy: the internal logic designed to clear session identifiers (`PS(id)`) between requests is wrapped in a preprocessor macro `#ifdef HAVE_PHP_SESSION`. This macro is only defined if the PHP session extension is statically linked at the time FrankenPHP is compiled.

When FrankenPHP is deployed using packages that utilize a shared PHP session extension (common in many Linux distribution repositories), the cleanup function is excluded from the binary. Consequently, worker threads retain the session state from the previous request. If a subsequent request arrives, the `session_start()` function may reuse the stale session identifier instead of parsing the cookie provided by the current client. This results in session hijacking or cross-user data exposure, impacting any FrankenPHP worker mode deployment relying on shared-module PHP builds (v1.12.4 and earlier).

## Attack Chain

1. Attacker identifies a target server running FrankenPHP in worker mode with a shared `session` extension.
2. Attacker maintains an active session (Session A) and observes that the application uses cookie-based session tracking.
3. Attacker sends a high volume of concurrent requests to the target, alternating between their Session A and a second controlled Session B.
4. The FrankenPHP worker thread serves Request 1 for User A, leaving the session ID in `PS(id)` memory space.
5. The same worker thread processes Request 2 for User B. Because the session state was not reset, the application fails to re-read the provided cookie and instead defaults to the lingering ID from User A.
6. The server returns a response to User B that includes data or state associated with User A, confirming the cross-user leak.

## Impact

The vulnerability results in critical session exposure, where a user may be assigned an arbitrary, foreign session ID, leading to account takeover or unauthorized access to other users' data. This behavior is persistent under load in multi-worker environments. Deployment on standard Linux package manager distributions (RPM/Debian) that ship PHP as shared modules is highly likely to be affected.

## Recommendation

- Upgrade to a FrankenPHP build where the `session` extension is statically linked, such as the official static binaries or Docker images.
- If upgrading is not immediately possible, implement an application-level workaround by calling `session_id('')` immediately after `session_write_close()` in the worker loop to force a re-read of session cookies on the next request.
- Audit current environment deployment configurations to determine if the `session` extension is loaded as a shared module via `conf.d` or statically compiled into the PHP-ZTS binary.

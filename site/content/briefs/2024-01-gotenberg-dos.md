---
title: Gotenberg Denial of Service via Context Pool Reuse
slug: 2024-01-gotenberg-dos
description: Gotenberg versions 8.31.0 and earlier are vulnerable to an unauthenticated denial-of-service attack where a race condition in the webhook middleware causes a panic and process termination when handling concurrent requests.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - gotenberg
vendors:
  - Gotenberg
products:
  - Gotenberg
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-r33j-c622-r6qp
rules:
  - title: Detect Gotenberg Process Crashes
    description: Detects rapid restarts of the Gotenberg Docker container, which may indicate exploitation of CVE-2026-42594
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
  - title: Detect Webhook Requests to Gotenberg
    description: Detect requests with the Gotenberg-Webhook-Url header to monitor for potential abuse of webhooks
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Gotenberg, a Docker-based stateless API for PDF files, is susceptible to a denial-of-service vulnerability (CVE-2026-42594) affecting versions 8.31.0 and earlier. The vulnerability stems from a race condition within the webhook middleware related to the reuse of `echo.Context` objects. When a webhook is triggered, the middleware spawns a goroutine and returns `ErrAsyncProcess`. This allows the Echo framework to recycle the context object back into a pool. If a concurrent request reclaims this context, the `c.Reset()` function clears the store. Should the webhook goroutine then reach the `hardTimeoutMiddleware`, an unchecked type assertion on a nil store entry will cause a panic, crashing the entire Gotenberg process. This vulnerability is exploitable by unauthenticated attackers capable of sending requests to the Gotenberg API, leading to service unavailability.

## Attack Chain

1. An attacker sends a request to the Gotenberg API that triggers a webhook (e.g., by using the `/forms/chromium/convert/html` endpoint with `Gotenberg-Webhook-Url` header).
2. The Gotenberg API spawns a goroutine to handle the webhook asynchronously and returns `api.ErrAsyncProcess`.
3. The Echo framework returns the `echo.Context` object to its internal pool.
4. A concurrent request acquires the recycled `echo.Context` object from the pool.
5. The `c.Reset()` function within Echo is called, clearing the `c.store` of the recycled context.
6. The webhook goroutine eventually executes, and calls `next(c)`, which leads to the `hardTimeoutMiddleware`.
7. Inside the `hardTimeoutMiddleware`, the code attempts to access the logger using `c.Get("logger").(*slog.Logger)`.
8. Since the context has been reset, `c.Get("logger")` returns nil, causing a panic due to the unchecked type assertion `nil.(*slog.Logger)`, which terminates the Gotenberg process.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition. The Gotenberg process crashes, interrupting any ongoing PDF conversions and causing the service to become unavailable. While auto-restart policies may restore the service, a sustained attack can keep the process in a constant restart loop, leading to prolonged unavailability. Because no authentication is required, any client capable of sending requests to the Gotenberg API can trigger the crash, making it easy to exploit.

## Recommendation

*   Apply the recommended fix by patching `pkg/modules/api/middlewares.go:398` to guard the type assertion with a nil check as suggested in the advisory.
*   Implement the `defer recover()` at the beginning of the webhook goroutine at `pkg/modules/webhook/middleware.go:338` to prevent panics from crashing the process.
*   Deploy the following Sigma rule to detect rapid Gotenberg process restarts which may indicate exploitation of this vulnerability: (see "Detect Gotenberg Process Crashes" rule below).

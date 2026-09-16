---
title: Multi-tenant Isolation Bypass in djust via WebSocket/SSE
slug: 2026-09-djust-tenant-isolation
description: A vulnerability in djust caused multi-tenant isolation to fail open on WebSocket and SSE paths, allowing unauthorized cross-tenant data disclosure due to improper tenant context propagation.
date: "2026-09-16T19:07:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:djust:djust:*:*:*:*:*:*:*:*
vendors:
  - djust
products:
  - djust (< 1.0.7)
cves:
  - id: CVE-2026-61595
    cvss: 7.7
references:
  - https://github.com/advisories/GHSA-3492-cvg7-9mr2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade djust to 1.0.7
      owner: Development
      due: 24h
      evidence: Fixed in djust 1.0.7
  mitigation_plan:
    - priority: immediate
      action: Upgrade to djust 1.0.7
      owner: IT Operations
      addresses: CVE-2026-61595
      evidence: Fixed in djust 1.0.7
---

The djust package (versions prior to 1.0.7) suffers from a critical multi-tenant isolation failure affecting WebSocket and Server-Sent Events (SSE) connections. The vulnerability stems from the implementation of tenant identification, which relied on `threading.local()` and an HTTP-only middleware. Because this middleware was not invoked on persistent connection paths (WebSocket/SSE), the `get_current_tenant()` function returned `None`. 

Consequently, the tenant-aware `QuerySet` manager failed in an open state, returning unfiltered data instead of restricting access to the current tenant. This issue was compounded by the use of `sync_to_async` executors, which shared thread-local storage across disparate connection contexts. This vulnerability allows an authenticated attacker to access data belonging to other tenants by initiating a WebSocket or SSE connection. The issue is addressed in version 1.0.7 by transitioning to `contextvars.ContextVar` and ensuring secure tenant binding during connection dispatch.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive data across all tenants within a djust-powered application. As the system defaults to returning unfiltered query sets when the tenant context is missing, any user with access to an active WebSocket or SSE endpoint can view records intended for other users or organizations. This vulnerability affects all applications using djust versions below 1.0.7 that utilize live connection features.

## Recommendation

- Upgrade the djust package to version 1.0.7 or later immediately to resolve CVE-2026-61595.
- After upgrading, verify that the application triggers system check S006 if `STRICT_MODE` is disabled, as this check warns when tenant isolation protections are lowered.
- Audit application logs for abnormal access patterns on WebSocket and SSE endpoints that may indicate unauthorized data harvesting from cross-tenant query results.

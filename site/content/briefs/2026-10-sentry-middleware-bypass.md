---
brief_id: brief-2026-10-22-sentry-middleware-bypass
event_id: brief-2026-10-22-sentry-middleware-bypass
revision: 1
activity_at: "2026-10-22T20:00:27Z"
title: 'Sentry-Javascript: Middleware bypass via tunnelRoute (CVE-2026-114139)'
slug: 2026-10-sentry-middleware-bypass
description: A middleware bypass vulnerability in the @sentry/nextjs SDK allows unauthenticated access to routes if the configured tunnel path overlaps with application routes in Webpack-based builds.
date: "2026-10-22T20:00:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source verified; patch versions confirmed
cpes:
  - cpe:2.3:a:sentry:sentry-javascript:*:*:*:*:*:*:*:*
tags:
  - web-application
  - middleware-bypass
  - cve-2026-114139
vendors:
  - Sentry
products:
  - '@sentry/nextjs (>= 9.36.0, < 9.47.2)'
  - '@sentry/nextjs (>= 10.0.0-alpha.0, < 10.75.2)'
  - '@sentry/nextjs (>= 11.0.0-alpha.0, < 11.0.0-rc.1)'
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    evidence: The middleware skip was wider than the rewrite. The skip applied to anything under the tunnel path.
    confidence_band: high
cves:
  - id: CVE-2026-114139
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-mchm-gjx6-7h55
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade @sentry/nextjs to patched versions (9.47.2, 10.75.2, or 11.0.0-rc.1)
      owner: IT Operations
      due: 48h
      evidence: Sentry GHSA patch information
  mitigation_plan:
    - priority: immediate
      action: Review tunnelRoute configuration for route collisions with internal application paths
      owner: Application Security
      addresses: CVE-2026-114139
      evidence: Source workaround guidance
---

The @sentry/nextjs SDK contains a middleware bypass vulnerability (CVE-2026-114139) affecting Webpack-based builds when the `tunnelRoute` option is configured. The SDK is designed to forward browser events to a specific path (the tunnel) while skipping middleware to prevent request rejection. However, the logic incorrectly skips middleware for all requests under the tunnel path, not just those intended for Sentry. If an application route resolves under the configured tunnel path, and that route relies exclusively on middleware for authorization, an attacker can bypass these checks. Sentry services and organization data are not affected.

## Impact

Successful exploitation allows unauthorized access to application routes that rely solely on middleware for authorization. Impact is limited to routes that overlap with the `tunnelRoute` path. Access to the route is not granted additional privileges; routes with internal server-side session validation remain protected.

## Recommendation

- Upgrade `@sentry/nextjs` to version 9.47.2, 10.75.2, or 11.0.0-rc.1 or later to apply the patch that restricts middleware skipping to the specific tunnel rewrite.
- If immediate patching is not possible, modify the `tunnelRoute` configuration to a path that does not collide with existing application routes.
- Enforce authorization checks within the route handlers, layouts, or data-access layers in addition to middleware, following a defense-in-depth approach.
- Transition to Turbopack for builds, as it is not affected by this specific implementation flaw.

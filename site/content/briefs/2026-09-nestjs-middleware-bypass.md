---
title: Path-Scoped Middleware Bypass in @nestjs/platform-fastify
slug: 2026-09-nestjs-middleware-bypass
description: An improper handling of absolute-form HTTP request targets in @nestjs/platform-fastify allows attackers to bypass path-scoped middleware by inducing a path resolution mismatch between the router and the middleware layer.
date: "2026-09-30T16:30:22Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - middleware-bypass
  - web-application-security
  - nestjs
  - fastify
  - npm
vendors:
  - NestJS
products:
  - '@nestjs/platform-fastify (< 11.2.4)'
  - '@nestjs/platform-fastify (12.0.0 - 12.0.1)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An HTTP request that uses an absolute-form request target reaches the route handler without running the path-scoped Nest middleware bound to that route.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Applications that enforce authentication or authorization in middleware execute the protected handler with those checks skipped.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Development Team
  immediate_actions:
    - action: Upgrade @nestjs/platform-fastify to the latest patched version.
      owner: Development Team
      due: 48h
      evidence: Fixed in 12.0.2 and 11.2.4. Upgrading to 12.0.3 or 11.2.5 is recommended.
  mitigation_plan:
    - priority: immediate
      action: Implement a request target validation hook in Fastify instance.
      owner: Development Team
      addresses: Absolute-form request target bypass
      evidence: Reject non-origin-form request targets before middleware runs.
---

A security vulnerability in the `@nestjs/platform-fastify` package (versions < 11.2.4 and 12.0.0 to 12.0.1) allows for the bypass of path-scoped middleware. The issue originates from inconsistent path normalization between the Fastify router and the middleware engine (a bundled fork of `@fastify/middie`). When an attacker crafts an HTTP request using an absolute-form request target (e.g., `GET http://host/path HTTP/1.1`) rather than the standard origin-form (`GET /path HTTP/1.1`), the middleware layer fails to recognize the path correctly. Consequently, requests reach their destination route handlers without triggering path-bound security controls such as authentication, authorization, or rate-limiting. This vulnerability is particularly critical for applications that rely solely on NestJS middleware to enforce access controls on sensitive API endpoints. The issue was addressed by ensuring consistent path resolution and updating the underlying middleware engine dependency to version 9.3.4.

## Attack Chain

1. Attacker performs reconnaissance to identify protected endpoints secured by NestJS middleware.
2. Attacker crafts a raw HTTP request using an absolute-form target containing the target path.
3. Attacker bypasses reverse proxies if the proxy configuration does not rewrite absolute-form request targets.
4. The Fastify router resolves the absolute-form request to the legitimate route handler, bypassing the middleware mismatch.
5. The `@nestjs/platform-fastify` middleware engine receives the absolute-form target and fails to match the configured route path due to lack of normalization.
6. The application executes the controller logic for the requested endpoint without triggering the authentication or authorization middleware.
7. Attacker successfully retrieves protected data or performs unauthorized actions.

## Impact

Successful exploitation results in authentication or authorization bypass for specific API endpoints secured by NestJS middleware. This can lead to unauthorized data access, administrative command execution, or the circumvention of rate-limiting and logging controls. The impact is dependent on the sensitivity of the handlers protected by the bypassed middleware. Applications that rely on external perimeter security or reverse proxies that enforce origin-form rewriting are partially protected from this vector.

## Recommendation

1. Upgrade `@nestjs/platform-fastify` to version 11.2.4 or 12.0.2 (recommended 11.2.5 or 12.0.3) to resolve the underlying path resolution mismatch.
2. If an immediate upgrade is not possible, implement a validation hook on the Fastify instance to reject non-origin-form request targets before the application processes the request.
3. Configure edge reverse proxies (such as Nginx or HAProxy) to rewrite incoming absolute-form request targets to origin-form to normalize traffic before it reaches the application.
4. Utilize the provided proof-of-concept script using Node.js net sockets to verify that current deployments reject non-standard request line formats.

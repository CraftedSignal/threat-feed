---
title: Strawberry GraphQL Permission Bypass via Awaitable Truthiness
slug: 2026-10-strawberry-graphql-bypass
description: Strawberry GraphQL's PermissionExtension incorrectly handles synchronous custom permission checks that return awaitable objects, allowing unauthorized access to protected fields due to Python's truthy evaluation of unawaited coroutines.
date: "2026-10-09T15:27:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:strawberry:strawberry-graphql:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - graphql
  - application-vulnerability
vendors:
  - Strawberry
products:
  - strawberry-graphql (0.217.0 - 0.326.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An application using a custom permission whose has_permission is a normal def returning an awaitable can unintentionally grant access to the protected field.
    confidence_band: high
cves:
  - id: CVE-2026-107728
    cvss: 7.5
    epss: 0.00353
references:
  - https://github.com/advisories/GHSA-pfvf-fwfp-25mp
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-107728
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Engineering
  immediate_actions:
    - action: Upgrade strawberry-graphql to 0.326.1 or later
      owner: Development
      due: 48h
      evidence: 'Source states: The synchronous path now fails closed: if has_permission() returns an awaitable, an error is raised instead of granting access.'
  mitigation_plan:
    - priority: immediate
      action: Review custom BasePermission subclasses for synchronous methods returning awaitables.
      owner: Security Engineering
      addresses: CVE-2026-107728
      evidence: Source provides proof-of-concept demonstrating the vulnerable pattern.
---

Strawberry GraphQL (versions 0.217.0 through 0.326.0) contains an authorization bypass vulnerability within `PermissionExtension.resolve()` in `strawberry/permission.py`. When a developer defines a custom permission class with a `has_permission` method using a standard `def` (instead of `async def`) that returns an awaitable result (such as a coroutine), the framework fails to await the result or check its resolved value. Because Python evaluates an unawaited awaitable object as truthy, the authorization check unconditionally grants access, bypassing intended security controls on the protected GraphQL field. 

This issue affects any application using custom permission classes where `has_permission` does not return a direct boolean or utilize `async def`. Standard `async def` permissions or those returning explicit boolean values remain unaffected. The flaw impacts both `execute_sync()` and `execute()` paths for fields utilizing synchronous resolvers.

## Attack Chain

1. Attacker identifies a GraphQL field protected by a custom `strawberry.permission.BasePermission` class.
2. The custom permission class is misconfigured such that `has_permission` is defined as a synchronous `def` that returns a coroutine object rather than a boolean.
3. Attacker sends a standard GraphQL query requesting data from the protected field.
4. The Strawberry GraphQL engine invokes `PermissionExtension.resolve()` during the resolution of the requested field.
5. `PermissionExtension.resolve()` checks the truthiness of the returned object from `has_permission()`.
6. Python evaluates the unawaited coroutine as `True` (truthy).
7. The framework treats the authorization as granted, bypassing the logic intended to block the request.
8. The underlying field resolver is executed, and the sensitive data is returned in the GraphQL response to the attacker.

## Impact

Successful exploitation results in unauthorized access to GraphQL fields intended to be protected by custom permission logic. This may lead to the exposure of sensitive data, unauthorized state changes, or the bypass of business logic checks, depending on what the specific permission-protected resolver performs. The impact is limited to applications that implement custom permission classes matching the vulnerable `has_permission` function signature.

## Recommendation

Prioritize auditing custom permission classes within your Strawberry GraphQL implementation to identify any `has_permission` definitions that return awaitables rather than explicit boolean values.

- Upgrade `strawberry-graphql` to a version containing the fix for CVE-2026-107728.
- Review all classes inheriting from `strawberry.permission.BasePermission` to ensure `has_permission` functions are either standard methods returning booleans or are explicitly defined as `async def` for asynchronous logic.
- If using asynchronous logic, verify that the application properly utilizes `resolve_async()` or ensure all permission checks are correctly awaited before boolean evaluation.

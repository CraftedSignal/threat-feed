---
title: Quarkus Vertx HTTP Authorization Bypass via Matrix Parameters
slug: 2026-05-quarkus-auth-bypass
description: Quarkus Vertx HTTP versions < 3.20.6.1, >= 3.21.0 and < 3.27.3.1, >= 3.30.0 and < 3.33.1.1, and >= 3.34.0 and < 3.35.1.1 are vulnerable to an authorization bypass where appending a semicolon and arbitrary text to the request URL allows unauthorized access to protected resources.
date: "2026-05-04T17:20:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - authorization-bypass
  - web-application
vendors:
  - Red Hat
products:
  - Quarkus Vertx HTTP (< 3.20.6.1)
  - Quarkus Vertx HTTP (>= 3.21.0, < 3.27.3.1)
  - Quarkus Vertx HTTP (>= 3.30.0, < 3.33.1.1)
  - Quarkus Vertx HTTP (>= 3.34.0, < 3.35.1.1)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-rc95-pcm8-65v9
rules:
  - title: Detect Quarkus Authorization Bypass Attempt
    description: Detects attempts to bypass authorization in Quarkus applications by using semicolons in the URL path.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Monitor Semicolons in URL Path
    description: Monitors web server logs for requests containing semicolons in the URL path, which could indicate potential authorization bypass attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists in Quarkus Vertx HTTP versions < 3.20.6.1, >= 3.21.0 and < 3.27.3.1, >= 3.30.0 and < 3.33.1.1, and >= 3.34.0 and < 3.35.1.1. The vulnerability, designated as CVE-2026-39852, allows unauthenticated or lower-privileged users to bypass HTTP path-based authorization policies. By appending a semicolon (`;`) and arbitrary text to the request URL, attackers can gain unauthorized access to protected resources. This vulnerability stems from an inconsistency in path normalization: Quarkus's security layer checks the raw URL path, while RESTEasy Reactive's routing layer strips matrix parameters before matching endpoints. This means a request like `/api/admin;anything` can bypass authorization for `/api/admin` while still routing to the protected endpoint. This issue was discovered and verified by the GitHub Security Lab.

## Attack Chain

1.  An attacker identifies a protected endpoint, such as `/api/admin`, that requires authentication or specific privileges.
2.  The attacker crafts a malicious HTTP request targeting the protected endpoint but appends a semicolon and arbitrary text, such as `/api/admin;anything`.
3.  The request is sent to the Quarkus Vertx HTTP server.
4.  Quarkus's security layer performs an authorization check on the raw URL path `/api/admin;anything`, which may not match the intended authorization rules for `/api/admin`.
5.  RESTEasy Reactive's routing layer strips the matrix parameters (`;anything`) from the URL, resulting in the endpoint `/api/admin` being matched.
6.  The request is routed to the protected endpoint `/api/admin`, bypassing the intended authorization checks.
7.  The attacker gains unauthorized access to the protected resource or functionality.
8.  The attacker performs actions they would not normally be authorized to perform, such as accessing sensitive data or modifying system configurations.

## Impact

Successful exploitation of this vulnerability can lead to unauthorized access to sensitive data, modification of system configurations, or other malicious activities. The vulnerability affects Quarkus Vertx HTTP applications that rely on path-based authorization policies. The number of affected applications is currently unknown, but any application using the vulnerable versions of Quarkus Vertx HTTP is susceptible.

## Recommendation

*   Upgrade Quarkus Vertx HTTP to a patched version (>= 3.20.6.1, >= 3.27.3.1, >= 3.33.1.1, >= 3.35.1.1) to remediate CVE-2026-39852.
*   Deploy the Sigma rule `Detect Quarkus Authorization Bypass Attempt` to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for requests containing semicolons in the URL path to detect potential exploitation attempts using the `Monitor Semicolons in URL Path` Sigma rule.

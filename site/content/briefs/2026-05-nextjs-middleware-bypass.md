---
title: Next.js Middleware Authorization Bypass via Dynamic Route Parameter Injection (CVE-2026-44574)
slug: 2026-05-nextjs-middleware-bypass
description: A vulnerability in Next.js (CVE-2026-44574) allows for authorization bypass in applications that use middleware to protect dynamic routes, enabling attackers to render protected content without proper authorization by crafting specific query parameters.
date: "2026-05-11T15:56:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nextjs
  - middleware
  - authorization
  - bypass
  - CVE-2026-44574
  - cloud
vendors:
  - npm
products:
  - next (>= 15.4.0, < 15.5.16)
  - next (>= 16.0.0, < 16.2.5)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
references:
  - https://github.com/advisories/GHSA-492v-c6pp-mqqv
rules:
  - title: Detect CVE-2026-44574 Exploitation Attempt — Next.js Middleware Bypass
    description: Detects CVE-2026-44574 exploitation attempt — suspicious HTTP requests to dynamic Next.js routes with encoded characters or unusual query parameters, potentially indicating a middleware bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect suspicious slash encoding in URI
    description: Detects requests with a slash encoding (%2F) in the URI
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

A high-severity vulnerability, CVE-2026-44574, affects Next.js applications that rely on middleware for authorization of dynamic routes. This flaw allows attackers to bypass middleware checks by manipulating query parameters to alter the perceived route, granting access to protected content without proper authentication or authorization. This issue impacts Next.js versions 15.4.0 through 15.5.15 and 16.0.0 through 16.2.4. Successful exploitation leads to unauthorized access to sensitive data and functionalities within the affected application. Defenders should prioritize patching or implementing workarounds to mitigate the risk of exploitation.

## Attack Chain

1. The attacker identifies a Next.js application using middleware for route protection.
2. The attacker discovers a dynamic route protected by middleware (e.g., `/dashboard/[id]`).
3. The attacker crafts a malicious URL containing manipulated query parameters designed to alter the dynamic route value. For example, `/dashboard/evil%2Fpath?param=value`.
4. The manipulated URL is sent to the Next.js application.
5. The application's routing logic incorrectly interprets the altered route value, bypassing the middleware check intended for the original route.
6. The application renders the protected content associated with the manipulated route.
7. The attacker gains unauthorized access to sensitive information or functionalities.

## Impact

Successful exploitation of CVE-2026-44574 allows attackers to bypass authorization checks in Next.js applications that rely on middleware for route protection. This can lead to unauthorized access to sensitive data, such as user profiles, financial records, or confidential documents. The impact is highly dependent on the specific application and the data it handles. Organizations using vulnerable Next.js versions should consider the potential for data breaches and unauthorized access to critical functionalities.

## Recommendation

*   Upgrade Next.js to version 15.5.16 or later, or 16.2.5 or later, to remediate CVE-2026-44574.
*   If immediate upgrading is not possible, enforce authorization checks within the route or page logic itself, instead of relying solely on middleware path matching as recommended in the advisory.
*   Deploy the Sigma rule "Detect CVE-2026-44574 Exploitation Attempt — Next.js Middleware Bypass" to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for suspicious URL patterns containing encoded characters or unusual query parameters targeting dynamic routes.

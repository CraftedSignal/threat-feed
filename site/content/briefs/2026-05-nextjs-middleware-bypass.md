---
title: Next.js Middleware/Proxy Bypass via Segment Prefetch
slug: 2026-05-nextjs-middleware-bypass
description: Next.js is vulnerable to a middleware/proxy bypass in App Router applications. Specially crafted `.rsc` and segment-prefetch URLs can resolve to the same page without being matched by the intended middleware rule, allowing protected content to be reached without the expected authorization check. The vulnerability affects Next.js versions greater than or equal to 15.2.0 and less than 15.5.16, as well as versions greater than or equal to 16.0.0 and less than 16.2.5.
date: "2026-05-11T15:56:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - next.js
  - middleware bypass
  - authorization
  - CVE-2026-44575
vendors:
  - Next.js
products:
  - next.js (>= 15.2.0, < 15.5.16)
  - next.js (>= 16.0.0, < 16.2.5)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://github.com/advisories/GHSA-267c-6grr-h53f
  - CVE-2026-44575
rules:
  - title: Detect Next.js Middleware Bypass Attempt via .rsc Extension
    description: Detects CVE-2026-44575 exploitation — attempts to bypass Next.js middleware by requesting .rsc resources.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1210
    data_sources:
      - webserver
  - title: Detect Next.js Middleware Bypass Attempt via Segment Prefetch
    description: Detects CVE-2026-44575 exploitation — attempts to bypass Next.js middleware by using segment prefetch routes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1210
    data_sources:
      - webserver
rules_count: 2
---

Next.js, a React framework for building web applications, is susceptible to a middleware/proxy bypass vulnerability within its App Router implementation. This vulnerability, identified as CVE-2026-44575, allows attackers to potentially circumvent authorization checks intended to protect specific content. The issue arises from the framework's handling of transport-specific route variants used for segment prefetching. The versions affected are Next.js versions greater than or equal to 15.2.0 and less than 15.5.16, as well as versions greater than or equal to 16.0.0 and less than 16.2.5. This can lead to unauthorized access to sensitive data or functionalities if middleware or proxy-based authorization is the sole means of protection.

## Attack Chain

1. An attacker identifies a Next.js application using the App Router with middleware-protected routes.
2. The attacker crafts a special URL targeting a protected resource, appending the `.rsc` extension or using segment prefetch routes.
3. The crafted URL bypasses the middleware checks, which are not correctly applied to these transport-specific variants.
4. The Next.js application processes the request for the `.rsc` or segment-prefetch route without invoking the authorization middleware.
5. The application retrieves the protected content associated with the route.
6. The application sends the protected content back to the attacker, effectively bypassing the intended access controls.
7. The attacker gains unauthorized access to the protected resource.

## Impact

Successful exploitation of this vulnerability, CVE-2026-44575, can lead to unauthorized access to sensitive information or functionalities within Next.js applications. The impact is highly dependent on the specifics of the application and the data it handles, but could include data breaches, privilege escalation, or other security compromises. The number of affected applications could be substantial, given Next.js's widespread adoption for modern web development.

## Recommendation

*   Upgrade to Next.js version 15.5.16 or 16.2.5 or later to patch CVE-2026-44575, as recommended by the vendor.
*   Deploy the Sigma rule "Detect Next.js Middleware Bypass Attempt via .rsc Extension" to detect malicious requests attempting to exploit this vulnerability.
*   If an immediate upgrade is not possible, enforce authorization checks within the underlying route or page logic as a workaround, as recommended by the vendor.

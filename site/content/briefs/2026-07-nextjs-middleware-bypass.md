---
title: Next.js App Router Middleware/Proxy Bypass Vulnerability (CVE-2026-64642)
slug: 2026-07-nextjs-middleware-bypass
description: A high-severity vulnerability, CVE-2026-64642, in Next.js App Router applications built with Turbopack and configured with a single locale entry allows attackers to bypass middleware and proxy-based authentication mechanisms through specially crafted HTTP requests, leading to unauthorized access to protected resources.
date: "2026-07-22T23:04:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - middleware-bypass
  - next.js
  - turbopack
  - CVE-2026-64642
vendors:
  - Vercel
products:
  - Next.js (>= 16.0.0, < 16.2.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Crafted requests targeting Next.js applications using App Router built with Turbopack and a single entry in config.i18n.locales can bypass middleware/proxy based authentication.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: can bypass middleware/proxy based authentication.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6gpp-xcg3-4w24
  - https://github.com/vercel/next.js/releases/tag/v16.2.11
---

A critical vulnerability, tracked as CVE-2026-64642, has been identified in Next.js applications utilizing the App Router, built with Turbopack, and configured with a single entry in `config.i18n.locales`. This flaw enables an unauthenticated attacker to craft specific HTTP requests that bypass authentication mechanisms implemented via middleware or a proxy. The vulnerability allows unauthorized access to resources and data that should otherwise be protected, potentially compromising the confidentiality of sensitive information. This issue affects Next.js versions 16.0.0 up to, but not including, 16.2.11, and was patched in version 16.2.11. Defenders need to prioritize patching to prevent unauthorized access to their applications.

## Attack Chain

1. An attacker identifies a public-facing Next.js application that uses the App Router, is built with Turbopack, and has a `config.i18n.locales` configuration with only one locale entry.
2. The attacker crafts a specially formed HTTP request, potentially manipulating URI paths, headers, or query parameters, targeting a resource typically protected by the application's middleware or proxy.
3. The Next.js application processes the crafted HTTP request before the middleware or proxy can correctly enforce authorization policies.
4. Due to the underlying logic flaw (CVE-2026-64642) related to Turbopack and single locale configuration, the application's routing mechanism inadvertently circumvents the authentication checks.
5. The attacker successfully bypasses the middleware or proxy-based authentication mechanism.
6. The application grants the attacker unauthorized access to protected pages, API routes, or other resources, enabling data exfiltration or further malicious actions depending on the nature of the exposed resources.

## Impact

Successful exploitation of CVE-2026-64642 results in unauthorized access to sensitive or protected resources within Next.js applications. This can lead to severe consequences, including the exposure of confidential user data, administrative credentials, or proprietary business information. Organizations relying on middleware or proxy layers for authentication and authorization in their Next.js App Router applications (versions >= 16.0.0, < 16.2.11) are at risk of data breaches and compromise of application integrity. While no specific victim counts or targeted sectors are provided, any organization running affected Next.js configurations is vulnerable.

## Recommendation

* Upgrade all affected Next.js App Router applications to version 16.2.11 or newer to remediate CVE-2026-64642 immediately.
* If immediate upgrade is not possible, enforce authorization checks directly within the page's server-side data fetching logic instead of solely relying on middleware for protection against CVE-2026-64642.

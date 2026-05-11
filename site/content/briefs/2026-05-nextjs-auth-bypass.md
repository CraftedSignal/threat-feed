---
title: Next.js i18n Pages Router Middleware Authentication Bypass (CVE-2026-44573)
slug: 2026-05-nextjs-auth-bypass
description: Next.js applications using the Pages Router with `i18n` and middleware-based authorization are vulnerable to an authentication bypass (CVE-2026-44573), allowing unauthorized access to protected page data via locale-less `/_next/data/<buildId>/<page>.json` requests.
date: "2026-05-11T15:56:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nextjs
  - authentication-bypass
  - vulnerability
vendors:
  - Next.js
products:
  - next (>= 12.2.0, < 15.5.16)
  - next (>= 16.0.0, < 16.2.5)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-36qx-fr4f-26g5
  - CVE-2026-44573
rules:
  - title: Detect Next.js i18n Auth Bypass Attempt
    description: Detects CVE-2026-44573 exploitation — attempts to bypass authentication on Next.js applications using i18n by requesting `/_next/data` without locale prefix.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555.003
    data_sources:
      - webserver
  - title: Detect Next.js Data Directory Access Attempt
    description: Detects access to the Next.js data directory, which can be used to expose application data in an i18n bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1555.003
    data_sources:
      - webserver
rules_count: 2
---

Next.js applications using the Pages Router with `i18n` enabled and relying on middleware or proxy-based authorization are susceptible to an authentication bypass vulnerability, tracked as CVE-2026-44573. This vulnerability affects Next.js versions 12.2.0 through 15.5.15 and 16.0.0 through 16.2.4.  The vulnerability stems from the fact that middleware does not execute for unprefixed `/_next/data/<buildId>/<page>.json` data routes when using `i18n`. An attacker can exploit this to directly retrieve server-side rendered (SSR) JSON data for protected pages, effectively bypassing the intended authorization checks implemented within the middleware. This allows access to sensitive content without proper authentication or authorization.

## Attack Chain

1.  The attacker identifies a Next.js application using the Pages Router with `i18n` configured.
2.  The attacker identifies a protected page that requires authentication or authorization based on middleware.
3.  The attacker crafts a request to `/_next/data/<buildId>/<page>.json` for the protected page, omitting any locale prefix. The `<buildId>` would be a valid build ID for the application, typically obtained from the HTML source of a page. The `<page>` is the path to the page.
4.  The Next.js server processes the request for the `/_next/data` route, but the middleware intended to protect the page is not triggered.
5.  The server fetches and returns the SSR JSON data for the protected page.
6.  The attacker receives the SSR JSON data, gaining access to the content of the protected page without proper authorization.
7.  The attacker analyzes the data, potentially finding sensitive information or API keys.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to sensitive data within Next.js applications. The impact depends on the nature of the data exposed on the protected pages. This could include personal user information, internal application data, or even API keys. This could lead to data breaches, account compromise, or further attacks against the application or its users.

## Recommendation

*   Upgrade to Next.js version 15.5.16 or 16.2.5 or later to patch CVE-2026-44573.
*   If immediate upgrade is not possible, enforce authorization checks within the `getServerSideProps` or `getStaticProps` functions of affected pages as a workaround.
*   Deploy the Sigma rule "Detect Next.js i18n Auth Bypass Attempt" to identify potential exploitation attempts targeting the `/_next/data` endpoint.
*   Monitor web server logs for requests to the `/_next/data` endpoint without a locale prefix, as this is indicative of potential exploitation.

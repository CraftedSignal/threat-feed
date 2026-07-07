---
title: '@asymmetric-effort/specifyjs: URL Parse Failure Silently Allows Request (CVE-2026-50288)'
slug: 2026-07-specifyjs-url-parse-failure
description: A high-severity vulnerability, CVE-2026-50288, in the `@asymmetric-effort/specifyjs` npm package (versions prior to 0.2.136) allows for the silent bypass of HTTPS validation by mishandling URL parse errors in the `assertSecureUrl` function, which can lead to Server-Side Request Forgery (SSRF).
date: "2026-07-03T11:47:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - npm
  - supply-chain
  - vulnerability
  - ssrf
  - javascript
vendors:
  - asymmetric-effort
products:
  - '@asymmetric-effort/specifyjs (< 0.2.136)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The `assertSecureUrl` function returned without throwing, silently allowing the request to proceed without HTTPS validation. This flaw can be exploited to achieve Server-Side Request Forgery (SSRF) by not ensuring that requests are directed to the intended destination.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8882-frvv-92w4
  - https://github.com/asymmetric-effort/specifyjs/commit/25d1fb4
  - https://github.com/asymmetric-effort/specifyjs/releases/tag/v0.2.136
---

A critical vulnerability, tracked as CVE-2026-50288, has been identified in the `@asymmetric-effort/specifyjs` npm package, specifically affecting versions prior to 0.2.136. This flaw resides within the `assertSecureUrl` function, intended to enforce HTTPS validation for URLs. The vulnerability occurs because the function's `catch` block for `new URL()` parse errors silently returns without re-throwing the error, effectively bypassing security checks. This oversight allows requests for malformed URLs to proceed without proper HTTPS validation, potentially enabling Server-Side Request Forgery (SSRF) attacks. Defenders should be aware that applications utilizing vulnerable versions of this library are susceptible to requests being directed to unintended or malicious destinations, jeopardizing internal network security and data integrity.

## Attack Chain

1.  An attacker identifies an application that uses the `@asymmetric-effort/specifyjs` library, specifically a vulnerable version (prior to 0.2.136).
2.  The attacker crafts a specially malformed URL that will cause `new URL()` to throw a parse error when processed by the `assertSecureUrl` function.
3.  The attacker sends this crafted URL to the vulnerable application, likely through a user-controlled input field that expects a URL.
4.  The application processes the input URL using the `assertSecureUrl` function for security validation.
5.  During validation, `new URL()` throws an error due to the malformed input provided by the attacker.
6.  Instead of re-throwing the error or blocking the request, the `assertSecureUrl` function's `catch` block silently returns, indicating success despite the parse failure and lack of HTTPS validation.
7.  The application proceeds to make a request to the unvalidated, and potentially attacker-controlled, internal or external endpoint.
8.  This successful bypass enables Server-Side Request Forgery (SSRF), allowing the attacker to access or manipulate internal resources, conduct port scanning, or exfiltrate sensitive data.

## Impact

The primary impact of CVE-2026-50288 is the potential for Server-Side Request Forgery (SSRF) within applications using vulnerable versions of the `@asymmetric-effort/specifyjs` library. Successful exploitation can allow attackers to force the compromised application server to make requests to internal services, retrieve sensitive data from internal systems (e.g., cloud metadata APIs, internal web services), bypass firewalls, or conduct port scanning of the internal network. Depending on the application's privileges and network access, this can lead to data exfiltration, further compromise of internal systems, or unauthorized actions against other resources, significantly impacting the confidentiality and integrity of the organization's data.

## Recommendation

*   Prioritize patching CVE-2026-50288 by upgrading `@asymmetric-effort/specifyjs` to version 0.2.136 or higher immediately. Refer to the GitHub Advisory Database reference for CVE-2026-50288.
*   Review your application's dependency tree to identify any instances of `@asymmetric-effort/specifyjs` at versions earlier than 0.2.136 and ensure all affected packages are updated.

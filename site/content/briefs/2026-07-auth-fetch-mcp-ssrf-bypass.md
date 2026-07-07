---
title: auth-fetch-mcp SSRF Protection Bypass via IPv4-mapped IPv6 Loopback
slug: 2026-07-auth-fetch-mcp-ssrf-bypass
description: auth-fetch-mcp versions up to and including 3.0.1 contain an SSRF protection bypass vulnerability (CVE-2026-49857) where the `isPrivateV6()` function fails to correctly identify IPv4-mapped IPv6 loopback addresses after Node.js URL normalization, allowing URLs like `http://[::ffff:127.0.0.1]:PORT/` to bypass the `assertSafeUrl()` check, enabling an attacker to coerce the `auth_fetch` or `download_media` tools to make requests to internal or loopback services and compromising the confidentiality of internal service responses.
date: "2026-07-03T12:43:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - bypass
  - node.js
  - initial-access
  - defense-evasion
products:
  - auth-fetch-mcp <= 3.0.1
affected_os:
  - Windows
  - Linux
  - macOS
references:
  - https://github.com/advisories/GHSA-pvrj-8cg3-j5f8
---

A high-severity Server-Side Request Forgery (SSRF) protection bypass vulnerability (CVE-2026-49857) has been identified in `auth-fetch-mcp` versions up to and including 3.0.1. The flaw resides in the `src/security.ts` module, specifically within the `isPrivateV6()` function, which is designed to prevent requests to private and loopback IP addresses. However, when a Node.js WHATWG URL parser hex-normalizes an IPv4-mapped IPv6 loopback address (e.g., `::ffff:127.0.0.1` becomes `::ffff:7f00:1`), the subsequent `net.isIPv4()` check incorrectly returns `false`. This bypasses the security control, allowing `auth_fetch` and `download_media` tools to access internal services. The issue has a CVSS v3.1 Base Score of 7.4 (High) and enables attackers to read sensitive information from internal services on the target system.

## Attack Chain

1. An attacker supplies a user-controlled URL argument (e.g., `http://[::ffff:127.0.0.1]:PORT/`) to the `auth_fetch` or `download_media` tools within `auth-fetch-mcp`.
2. The application's `navigateTo()` or `ctx.request.get()` function calls `assertSafeUrl()` to validate the provided URL against SSRF protections.
3. Inside `assertSafeUrl()`, the `isPrivateV6()` function is invoked to determine if the URL's hostname is a private IPv6 address.
4. The Node.js WHATWG URL parser silently normalizes the IPv4-mapped IPv6 address (e.g., `::ffff:127.0.0.1`) to its hex-normalized form (e.g., `::ffff:7f00:1`).
5. `isPrivateV6()` attempts to check the normalized address but `net.isIPv4('7f00:1')` incorrectly returns `false` because `7f00:1` is not a dotted-decimal IPv4 string.
6. This incorrect `false` result causes the `isPrivateV6()` and subsequently `assertSafeUrl()` functions to treat the loopback address as safe, bypassing the intended SSRF protection.
7. The now "validated" URL, which points to an internal loopback service, is then used by `page.goto()` (for `auth_fetch`) or `ctx.request.get()` (for `download_media`) to issue an HTTP request.
8. The application fetches content from the specified internal service, extracts it, and returns it to the attacker, thereby compromising the confidentiality of internal service responses.

## Impact

This Server-Side Request Forgery (SSRF) vulnerability allows an attacker who can control the `url` argument of `auth_fetch` or `download_media` to force the `auth-fetch-mcp` server to make HTTP requests to services on `127.0.0.1` or other private IPv4 ranges. This impacts end users running `auth-fetch-mcp` locally, where an attacker could read responses from local development servers, admin panels, or credential endpoints. Server-side deployments of `auth-fetch-mcp` face the same risk against internal network services. The confidentiality of internal service responses is fully compromised (C:H), as demonstrated by the ability to retrieve an `INTERNAL_SECRET_MARKER` from a simulated internal service. The integrity and availability of the target service are not directly affected.

## Recommendation

*   **Patch CVE-2026-49857**: Implement the proposed remediation outlined in the GHSA advisory, which involves decoding the hex-encoded IPv4-mapped suffix before passing it to `isPrivateV4()` in `src/security.ts`.
*   **Application-level Guard**: Add a `BrowserContext` route guard in `src/browser.ts` to re-validate every navigation URL, including redirect targets, using `assertSafeUrl()` for enhanced protection.
*   **Review `auth-fetch-mcp` usage**: If `auth-fetch-mcp` is exposed to user-controlled input, review configurations and consider restricting its ability to resolve arbitrary URLs until a patch for CVE-2026-49857 is available.

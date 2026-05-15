---
title: Better Auth Rate Limiter Bypass via IPv6 Prefix Rotation (CVE-2026-45364)
slug: 2026-05-better-auth-rate-limit-bypass
description: Better Auth versions before 1.4.17 and pre-release versions before 1.5.0-beta.9 are vulnerable to CVE-2026-45364, a rate-limiting bypass that allows IPv6 clients to rotate through numerous source addresses or vary the textual encoding of one IPv6 address, effectively defeating rate limiting on authentication endpoints, potentially leading to credential stuffing, account enumeration, and amplification of password-reset email fan-out.
date: "2026-05-15T17:43:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - rate-limiting
  - authentication
  - ipv6
  - cve-2026-45364
vendors:
  - Cloudflare
  - Vercel
  - Fly.io
  - AWS
  - Google
products:
  - better-auth
  - Cloudflare
  - Vercel Firewall
  - AWS WAF
  - Google Cloud Armor
references:
  - https://github.com/advisories/GHSA-p6v2-xcpg-h6xw
  - https://cwe.mitre.org/data/definitions/307.html
  - https://datatracker.ietf.org/doc/html/rfc4291
  - https://datatracker.ietf.org/doc/html/rfc5952
  - https://datatracker.ietf.org/doc/html/rfc6177
rules:
  - title: Detect High Volume Authentication Attempts from Single IPv6 /64 Prefix (CVE-2026-45364)
    description: Detects CVE-2026-45364 exploitation — high volume of failed authentication attempts originating from the same IPv6 /64 subnet, indicating potential rate-limiting bypass attempts.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588
    data_sources:
      - webserver
  - title: Detect Multiple Textual Variations of IPv6 Address (CVE-2026-45364)
    description: Detects CVE-2026-45364 exploitation — Multiple textual variations of the same IPv6 address used within a short timeframe. This may indicate an attempt to bypass rate limiting based on IP address.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1588
    data_sources:
      - webserver
rules_count: 2
---

Better Auth, a Node.js authentication library, is vulnerable to a rate-limiting bypass (CVE-2026-45364) affecting versions before 1.4.17 and pre-release versions before 1.5.0-beta.9. The vulnerability stems from the rate limiter keying requests by the exact textual IP address, allowing IPv6 clients to circumvent rate limits by rotating through numerous source addresses or manipulating the textual encoding of a single IPv6 address. This bypass impacts authentication endpoints like `/sign-in/email`, `/sign-up/email`, and `/forget-password`, making them susceptible to abuse. The issue was addressed in version 1.4.17 by introducing IP address normalization, which involves expanding compressed IPv6 forms, lowercasing hex digits, collapsing IPv4-mapped IPv6 to plain IPv4, and applying a default `/64` prefix mask. Managed hosts including Cloudflare, Vercel, Fly.io, AWS Application Load Balancer, and Google Cloud Load Balancing advertise IPv6 by default, increasing the attack surface.

## Attack Chain

1.  An attacker identifies an authentication endpoint (e.g., `/sign-in/email`) protected by Better Auth's rate limiter.
2.  The attacker sends a request to the authentication endpoint from an IPv6 address.
3.  The Better Auth rate limiter extracts the leftmost `x-forwarded-for` value without proper normalization.
4.  The attacker rotates the source IPv6 address within their assigned prefix (e.g., a /64 allocation) or modifies the textual encoding of the IPv6 address (e.g., using compressed or mixed forms).
5.  The attacker sends a subsequent request to the same endpoint, using the rotated or modified IPv6 address.
6.  The rate limiter treats the new IPv6 address as a distinct client due to the lack of normalization.
7.  The attacker repeats steps 4-6 to bypass the rate limit and make unlimited authentication attempts.
8.  The attacker performs credential stuffing, account enumeration, or password-reset amplification attacks.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass rate limiting on authentication endpoints. This can lead to credential stuffing attacks against `/sign-in/email`, enabling unauthorized access to user accounts. Account enumeration becomes easier due to the ability to make unlimited requests without being rate limited. Furthermore, attackers can amplify password-reset and email-verification email fan-out, potentially overwhelming email systems and causing denial of service. While this vulnerability does not directly compromise accounts, it weakens the defense-in-depth and increases the risk of successful attacks.

## Recommendation

*   Upgrade to `better-auth@1.4.17` or later to apply the fix that normalizes IPv6 addresses, mitigating the rate-limiting bypass (see Patches section).
*   If upgrading is not immediately feasible, and you are on `>= 1.4.16`, set `advanced.ipAddress.ipv6Subnet: 64` in the auth configuration to restore post-`1.4.17` behavior (see Workarounds section).
*   For versions `< 1.4.16`, shift the bypass mitigation upstream by configuring IPv6 prefix length limiting on your CDN, WAF, or load balancer to `/64` (or coarser per RFC 6177) (see Workarounds section).
*   Deploy the Sigma rule "Detect High Volume Authentication Attempts from Single IPv6 /64 Prefix (CVE-2026-45364)" to identify potential exploitation attempts by monitoring authentication logs for excessive attempts from the same /64 IPv6 subnet (see Rules section).

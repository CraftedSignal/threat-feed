---
title: SSRF Vulnerability in dssrf npm Package via DNS Resolver Logic
slug: 2026-07-dssrf-ssrf
description: The dssrf npm package (versions 1.0.4 and earlier) fails to correctly validate URLs when using 1.1.1.1 as a DNS resolver, incorrectly treating localhost as safe and enabling server-side request forgery (SSRF) when NXDOMAIN responses occur.
date: "2026-07-31T19:29:34Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - dssrf (<= 1.0.4)
cves:
  - id: CVE-2026-54729
references:
  - https://github.com/advisories/GHSA-5846-7qm3-r52j
  - CVE-2026-54729
---

The dssrf npm package contains a security vulnerability (CVE-2026-54729) that allows an attacker to bypass URL validation and perform server-side request forgery (SSRF). This issue specifically affects environments that utilize 1.1.1.1 as the configured DNS resolver. The vulnerability exists within the is_url_safe function, which fails to handle NXDOMAIN responses correctly. When the library attempts to resolve a target address, it does not properly fall back or account for cases where the DNS query for a seemingly malicious or internal address returns an NXDOMAIN result. As a consequence, the validation logic erroneously evaluates requests to localhost or other internal endpoints as safe. This vulnerability allows an attacker to interact with services on the host machine or internal network that would otherwise be protected by the library's URL filtering mechanisms. This impacts applications relying on dssrf for input sanitization of user-provided URLs.

## Impact

Successful exploitation of this vulnerability allows an attacker to perform SSRF attacks, potentially leading to unauthorized access to internal services, sensitive metadata endpoints, or administrative interfaces running on the same host or network as the application using the affected dssrf package.

## Recommendation

1. Upgrade the dssrf npm package to version 1.5.0 or later to include the fix for CVE-2026-54729.
2. If an immediate upgrade is not possible, review application configurations to ensure DNS resolution for restricted domains is performed using robust internal resolvers that do not exhibit the same handling behavior as 1.1.1.1 in this context.
3. Implement additional network-level ingress/egress filtering to prevent the application server from initiating connections to localhost or internal RFC1918 address space.

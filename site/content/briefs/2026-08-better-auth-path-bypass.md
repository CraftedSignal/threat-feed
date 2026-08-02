---
title: Better Auth Path Normalization Vulnerability (CVE-2025-71399)
slug: 2026-08-better-auth-path-bypass
description: Better Auth versions prior to 1.4.5 contain a path normalization vulnerability in the rou3 library that allows attackers to bypass disabledPaths configurations and rate limits via URL path manipulation.
date: "2026-08-02T13:35:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - web-application
  - security-bypass
  - cve-2025-71399
vendors:
  - Better Auth
products:
  - Better Auth
cves:
  - id: CVE-2025-71399
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71399
---

CVE-2025-71399 identifies a path normalization flaw within the Better Auth library, specifically stemming from its dependency on the rou3 router. In affected versions of rou3, the routing logic treats multiple consecutive slashes in a URL path as equivalent to a single slash (e.g., //path is treated as /path). Because the Better Auth library relies on this behavior for enforcing security controls, attackers can submit specially crafted requests with redundant slashes to bypass path-based security policies, including the disabledPaths configuration and rate-limiting rules. This vulnerability is applicable to deployments where the fronting web server, proxy, or load balancer does not perform URL normalization before passing the request to the application. Upgrading to Better Auth version 1.4.5 or later, which incorporates a patched version of the rou3 library, is required to mitigate this flaw.

## Impact

Successful exploitation allows an attacker to bypass critical security controls configured within Better Auth. By obfuscating requests with redundant slashes, unauthorized users may access restricted endpoints defined in disabledPaths or circumvent rate-limiting protections, potentially leading to unauthorized data access, unauthorized state changes, or service degradation through request flooding. The vulnerability is highly dependent on the ingress infrastructure configuration; environments that already enforce strict URL normalization at the reverse proxy level may not be susceptible.

## Recommendation

- Upgrade Better Auth to version 1.4.5 or later to resolve the underlying dependency issue.
- Implement URL normalization at the perimeter (reverse proxy, WAF, or load balancer) to ensure that incoming requests are consistent before reaching the application layer.
- Review current Better Auth disabledPaths configurations to ensure they are not solely relied upon for high-sensitivity access control, adhering to defense-in-depth principles.

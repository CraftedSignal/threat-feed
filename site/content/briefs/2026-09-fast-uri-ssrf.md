---
title: SSRF Vulnerability via IPv6 Normalization in fast-uri
slug: 2026-09-fast-uri-ssrf
description: The fast-uri library incorrectly normalizes malformed IPv6 bracketed literals, allowing attackers to bypass host-based security checks via SSRF.
date: "2026-09-03T00:04:28Z"
lastmod: "2026-09-03T00:04:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openjsf:fast-uri:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - web-application
  - supply-chain
products:
  - fast-uri (2.3.1 - 2.4.4)
  - fast-uri (3.0.0 - 3.1.5)
  - fast-uri (4.0.0 - 4.1.2)
  - fast-uri (v2.3.1 <= v < 2.4.5)
  - fast-uri (v3.0.0 <= v < 3.1.6)
  - fast-uri (v4.0.0 <= v < 4.1.3)
cves:
  - id: CVE-2026-75975
    cvss: 7.5
    epss: 0.00234
references:
  - https://github.com/advisories/GHSA-f65p-4m7j-42xc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75975
  - https://github.com/advisories/GHSA-jqff-g426-hqxp
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade fast-uri to versions 2.4.5, 3.1.6, or 4.1.3
      owner: IT Operations
      addresses: CVE-2026-75975
      evidence: Upgrade to fast-uri 2.4.5, 3.1.6, or 4.1.3. Malformed IPv6 literals are now rejected with a host error instead of being normalized to a valid address.
updates:
  - at: "2026-09-03T00:04:36Z"
    level: L2
    summary: added coverage for fast-uri (v2.3.1 <= v < 2.4.5) +2 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-jqff-g426-hqxp
---

The fast-uri library (versions 2.3.1 through 4.1.3) fails to properly validate the full RFC 3986 grammar for bracketed IPv6 address literals. When the library encounters a malformed IPv6 literal containing invalid trailing text, it incorrectly truncates the input and returns a valid IPv6 address without flagging an error. For example, inputs like `[::not-valid]` are normalized to `[::]`. 

This behavior creates a Server-Side Request Forgery (SSRF) risk. Applications that rely on fast-uri to normalize user-provided URLs before performing server-side host-policy checks or outbound requests may inadvertently route traffic to internal, private, or loopback IPv6 addresses. Because the library does not set the 'error' property on the parsed result for these malformed inputs, applications that rely on standard error checking will fail to detect the malformation, effectively bypassing security controls that were intended to prevent access to sensitive internal infrastructure.

## Impact

Successful exploitation allows an attacker to perform SSRF attacks against internal network resources. By supplying a URL containing a crafted IPv6 host, an attacker can coerce a vulnerable application into performing requests to private or loopback IPv6 addresses that would otherwise be blocked by an allowlist or security middleware. This can lead to unauthorized access to internal administrative interfaces, local services, or sensitive metadata endpoints. The impact is significant for applications that process user-controlled URLs and handle sensitive internal data or administrative tasks.

## Recommendation

- Upgrade fast-uri to versions 2.4.5, 3.1.6, or 4.1.3 to remediate CVE-2026-75975, which introduces proper rejection of malformed IPv6 literals.
- Implement a secondary validation layer that rejects or strips user-supplied URLs containing bracketed IPv6 literals if the application does not explicitly require them.
- Configure outbound request handlers to validate hostnames against an explicit, trusted allowlist of IP addresses or FQDNs before initiating the network connection.

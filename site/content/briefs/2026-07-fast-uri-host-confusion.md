---
title: Fast-uri Library Host Confusion Vulnerability (CVE-2026-16221)
slug: 2026-07-fast-uri-host-confusion
description: The `fast-uri` library, in versions prior to 4.1.1, 3.1.4, and 2.4.3, is vulnerable to a host confusion issue (CVE-2026-16221) due to its failure to treat a literal backslash as an authority delimiter, enabling attackers to bypass host-based security policies via Server-Side Request Forgery (SSRF) or unauthorized access to internal resources.
date: "2026-07-21T22:14:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - host-confusion
  - ssrf
  - dependency-vulnerability
  - node.js
products:
  - fast-uri <= 2.4.2
  - fast-uri >= 3.0.0, <= 3.1.3
  - fast-uri >= 4.0.0, <= 4.1.0
cves:
  - id: CVE-2026-16221
    cvss: 7.5
    epss: 0.00221
references:
  - https://github.com/advisories/GHSA-v2hh-gcrm-f6hx
---

A high-severity host confusion vulnerability, identified as CVE-2026-16221, exists in the `fast-uri` library, affecting versions 4.1.0 and earlier, as well as specific ranges within the v2 (2.3.1 through 2.4.2) and v3 (3.0.0 through 3.1.3) branches. This vulnerability stems from a parsing discrepancy where `fast-uri` does not recognize a literal backslash (U+005C) as an authority delimiter, unlike Node.js's native WHATWG `URL` parser (used by `fetch()`, `undici`, and Node's `http`/`https` clients). This allows an attacker to craft URLs that, when initially validated by `fast-uri` against host-based security policies (e.g., allowlists, denylists, SSRF filtering), appear benign, but are then reinterpreted by Node's URL consumers to point to an unintended, potentially malicious, destination. This disparity can lead to severe security bypasses, including Server-Side Request Forgery (SSRF) and unauthorized access to internal or cloud resources.

## Attack Chain

1. An attacker crafts a malicious URL containing a literal backslash (U+005C) within the host or authority segment for special schemes (e.g., `http://evil.com\internal.resource`).
2. An application receives this crafted URL and initially passes it to the vulnerable `fast-uri` library for enforcement of host-based security policies (e.g., allowlists, denylists, SSRF filtering).
3. The `fast-uri` library incorrectly parses the URL, considering the backslash as part of the path or userinfo rather than an authority delimiter, leading the security policy check to pass based on a seemingly benign or allowed host.
4. The application then takes the *same* URL string and passes it to Node.js's native WHATWG `URL` parser, `fetch()`, or `undici` for network requests.
5. Node.js's native URL parser, for special schemes like HTTP or HTTPS, normalizes the backslash (U+005C) to a forward slash (U+002F) and correctly identifies the true, potentially malicious, target host (e.g., `internal.resource`).
6. The application proceeds to make a network request to the unintended and unvalidated destination, bypassing the intended security policy.
7. This discrepancy between `fast-uri`'s parsing and Node's URL consumers results in a successful security policy bypass.
8. The attacker achieves objectives such as Server-Side Request Forgery (SSRF), unauthorized access to internal network services, or data exfiltration from sensitive endpoints like cloud metadata services.

## Impact

The successful exploitation of CVE-2026-16221 can lead to severe consequences for applications relying on `fast-uri` for URL validation. If an application uses `fast-uri` to enforce host-based policies (such as allowlists, denylists, or SSRF filtering) and then passes the same URL to Node.js's native URL or `fetch()` clients, an attacker can bypass these controls. This can steer the application to unintended destinations, including internal network hosts, loopback addresses, or cloud metadata endpoints. This allows for Server-Side Request Forgery (SSRF), unauthorized access to sensitive internal systems or data, and potential data exfiltration. The vulnerability could impact a broad range of Node.js applications that process URLs from untrusted sources and utilize the `fast-uri` library.

## Recommendation

* Upgrade the `fast-uri` library immediately to patched versions 4.1.1, 3.1.4, or 2.4.3 to remediate CVE-2026-16221.
* Ensure that all applications using `fast-uri` are updated to a non-vulnerable version to prevent host confusion and policy bypasses.

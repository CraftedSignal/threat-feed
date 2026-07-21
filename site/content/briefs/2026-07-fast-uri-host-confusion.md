---
title: fast-uri Host Confusion Vulnerability (CVE-2026-13676)
slug: 2026-07-fast-uri-host-confusion
description: The `fast-uri` library is vulnerable to host confusion due to improper canonicalization of Unicode/IDN hostnames in HTTP-family URLs, allowing an attacker to bypass host-based security policies by exploiting a discrepancy between how `fast-uri` and Node's native URL parser handle the same URL.
date: "2026-07-21T19:04:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openjsf:fast-uri:*:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - host-confusion
  - npm
  - library
vendors:
  - fast-uri
products:
  - fast-uri >= 4.0.0, < 4.0.1
  - fast-uri >= 3.0.0, < 3.1.3
  - fast-uri >= 2.3.1, < 2.4.2
cves:
  - id: CVE-2026-13676
    cvss: 7.5
    epss: 0.00369
references:
  - https://github.com/advisories/GHSA-4c8g-83qw-93j6
---

The `fast-uri` JavaScript library, specifically versions older than 2.4.2, between 3.0.0 and 3.1.3 (exclusive of 3.1.3), and between 4.0.0 and 4.0.1 (exclusive of 4.0.1), is susceptible to a host confusion vulnerability identified as CVE-2026-13676. This flaw arises because `fast-uri` fails to properly canonicalize Unicode or Internationalized Domain Name (IDN) hostnames in HTTP-family URLs. The core issue stems from an attempt to call `URL.domainToASCII` on the global WHATWG `URL` constructor, which does not exist, leading to a `TypeError` that is silently absorbed. Consequently, `fast-uri`'s `parse()`, `normalize()`, and `equal()` functions return URLs with hostnames in their original Unicode form (e.g., `http://127。0。0。1/`), while Node.js's native WHATWG `URL` parser and `fetch()` correctly canonicalize them to their ASCII equivalent (e.g., `http://127.0.0.1/`). This discrepancy can lead to a policy/use desync, allowing attackers to bypass host-based security controls implemented using `fast-uri`, such as denylists, loopback filtering, redirect validation, or outbound proxy routing, potentially steering applications to unintended or restricted destinations.

## Attack Chain

1. **Attacker crafts malicious URL:** An attacker creates a URL containing an Internationalized Domain Name (IDN) or Unicode characters that `fast-uri` will not properly canonicalize (e.g., `http://example。com` instead of `http://example.com`, or `http://127。0。0。1`).
2. **Application receives URL:** A vulnerable application receives this crafted URL, possibly from user input, a third-party API, or a redirect.
3. **fast-uri performs policy check:** The application uses `fast-uri` to evaluate host-based security policies, such as denylisting specific domains, enforcing loopback restrictions, or validating redirect targets.
4. **Canonicalization failure in fast-uri:** Due to the missing `URL.domainToASCII` helper in its execution environment, `fast-uri` fails to convert the IDN hostname to its ASCII form, leaving it as the original Unicode string. This leads to a `TypeError` silently routed to `parsed.error`.
5. **Policy bypass:** Because `fast-uri` retains the Unicode hostname (e.g., `127。0。0。1`), its policy checks, which typically compare against ASCII hostnames (e.g., `127.0.0.1`), fail to correctly identify the malicious or restricted host, allowing the URL to pass the policy.
6. **URL passed to Node's native parser:** The application then passes the *same, uncanonicalized URL* to Node.js's native `URL` constructor or `fetch()` API for actual network operations.
7. **Native canonicalization and connection:** Node.js's native URL parser correctly canonicalizes the IDN hostname (e.g., `127。0。0。1` becomes `127.0.0.1`), resolving to the attacker's intended target or a restricted local address.
8. **Unintended destination reached:** The application makes a connection or request to the unintended destination, effectively bypassing the security policy intended by `fast-uri`, leading to data exfiltration, Server-Side Request Forgery (SSRF), or other malicious actions.

## Impact

The successful exploitation of CVE-2026-13676 allows attackers to bypass critical host-based security policies implemented within applications using `fast-uri`. This includes bypassing denylists designed to block access to specific external domains, circumventing loopback filtering intended to prevent access to internal services (SSRF), and manipulating redirect validation mechanisms to direct users or systems to arbitrary destinations. The discrepancy in URL parsing between `fast-uri` and Node's native URL functionality means that even if `fast-uri` indicates a URL is safe or allowed, the underlying system might connect to a completely different, potentially malicious, or restricted host. This can lead to unauthorized data access, network reconnaissance, or other severe security breaches, depending on the context of the vulnerable application.

## Recommendation

* Upgrade the `fast-uri` package to a patched version immediately to resolve CVE-2026-13676. Specifically, upgrade to `fast-uri` v4.0.1, v3.1.3, or v2.4.2.
* Review applications that utilize `fast-uri` for URL parsing and host-based policy enforcement to ensure they are using a patched version.
* Ensure continuous monitoring for vulnerable dependencies in your development pipeline using tools that detect CVE-2026-13676.

---
title: SSRF via Ambiguous IPv4 Parsing in ip-address Library
slug: 2026-08-ip-address-ssrf
description: The ip-address library versions 10.3.0 and below incorrectly parse IPv4 addresses with leading zeros, leading to trust-boundary bypasses and SSRF when used to filter internal network access.
date: "2026-08-03T20:48:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - library-vulnerability
  - supply-chain
vendors:
  - npm
products:
  - ip-address (<= 10.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An application that builds a network trust-boundary decision on these checks (for example a filter intended to block Server-Side Request Forgery, or SSRF) will classify an internal target as external and allow the request.
    confidence_band: high
cves:
  - id: CVE-2026-69192
references:
  - https://github.com/advisories/GHSA-mwp4-54f8-5fhr
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-69192
---

The ip-address npm package (versions 10.3.0 and below) contains a critical flaw in its IPv4 parsing logic that creates an address-classification discrepancy between the application-layer guard and the underlying network resolver. The library's `Address4.parse` logic uses a regular expression that permits octets with leading zeros, which it then decodes as decimal. However, standard network resolvers and the WHATWG URL host parser interpret such leading-zero octets as octal (base 8).

This discrepancy allows an attacker to bypass security filters built on top of this library. For example, the host '012.0.0.1' is classified by the library as a public/external address, but when passed to a network utility or `fetch` request, the OS resolver interprets it as '10.0.0.1', a private RFC 1918 address. Applications relying on this library to validate URLs or block SSRF (Server-Side Request Forgery) will fail to detect these obfuscated internal addresses, allowing malicious requests to reach restricted internal infrastructure, such as management interfaces or metadata services.

## Attack Chain

1. Attacker identifies a target application utilizing the ip-address library to perform SSRF filtering or trust-boundary validation.
2. Attacker crafts an IPv4 address string using octal-ambiguous notation (e.g., '012.0.0.1') corresponding to a sensitive internal resource.
3. The application passes this string to `new Address4(host)` for security validation.
4. `Address4` validates the string as a non-private IPv4 address (or a non-loopback address) because it treats the leading zero as a decimal identifier.
5. The application security logic concludes the host is safe (not internal) and permits the request.
6. The application subsequently passes the untrusted string to a native URL parser or network request library (e.g., `fetch`, `axios`).
7. The network resolver interprets the leading zero as octal, resolving the address to an internal target (e.g., 10.0.0.1).
8. The final network request is dispatched to the prohibited internal destination, resulting in successful SSRF.

## Impact

Successful exploitation results in SSRF, allowing attackers to access internal-only services, cloud metadata endpoints, or local network resources that are shielded from the public internet. This bypass is effective because the obfuscation technique is compatible with standard URL parsing and network stacks, requiring no specialized tooling. The vulnerability affects any application that relies on `ip-address` to block internal IP ranges without performing secondary host resolution and socket-level verification.

## Recommendation

1. Upgrade the `ip-address` package to a patched version immediately.
2. If an immediate upgrade is not possible, implement an input filter that rejects any host whose octets contain a leading zero before passing it to the library: `if (host.split('.').some((octet) => /^0\d/.test(octet))) throw new Error('ambiguous address');`.
3. Ensure that all SSRF guards are implemented as multi-layered defenses. Do not rely solely on parsing libraries; perform actual DNS resolution of hostnames and validate the resolved IP against an allowed-list before establishing a socket connection.
4. Ensure security checks account for DNS rebinding and redirects, as static address validation is insufficient to prevent all SSRF scenarios.

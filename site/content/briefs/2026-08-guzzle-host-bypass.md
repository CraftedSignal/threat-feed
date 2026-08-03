---
title: Guzzle Hostname Validation Bypass via Transport Discrepancy
slug: 2026-08-guzzle-host-bypass
description: Guzzle versions before 7.15.2 and 8.0.1 are vulnerable to a host-based security check bypass where transport handlers interpret non-canonical URI hostnames differently than application-level validation, potentially enabling SSRF.
date: "2026-08-03T23:42:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - ssrf
  - php
  - vulnerability
  - web-security
vendors:
  - Guzzle
products:
  - Guzzle (7.x)
  - Guzzle (8.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who influences a fetched URI can therefore reach a host the application's checks excluded and read whatever it exposes of the response.
    confidence_band: high
cves:
  - id: CVE-2026-69246
    cvss: 7.2
references:
  - https://github.com/advisories/GHSA-v5mv-p594-2x33
  - CVE-2026-69246
---

Guzzle, a popular PHP HTTP client, contains a vulnerability (CVE-2026-69246) that allows an attacker to bypass application-level host validation checks. The vulnerability stems from a divergence between how Guzzle processes request URIs and how its underlying transport handlers (cURL and stream wrappers) resolve those same URIs. When an application performs security checks on a hostname - such as denylisting private IP ranges or verifying domain allowlists - it may inspect the URI as a string. However, when the request is handed to the transport layer, libcurl or fopen may parse, percent-decode, or apply IDNA mapping to the host, resulting in a connection to a destination the application intended to block. 

This issue is particularly dangerous when applications rely on `filter_var()` or similar mechanisms to validate hostnames, as these can be bypassed using non-canonical encodings like `127.0.0.%31`. The transport layer resolves this as the loopback address while the application incorrectly validates it as a different, non-local host. The vulnerability affects both the Guzzle 7.x and 8.x branches.

## Attack Chain

1. The attacker identifies an application feature that accepts user-provided URIs for fetching remote content.
2. The application parses the input URI and performs a security check (e.g., denying private IP ranges or internal hostnames).
3. The attacker provides a non-canonical URI (e.g., `http://127.0.0.%31/` or `blocked.example.com@127.0.0.1`) that passes the application's check but is misinterpreted by the Guzzle transport.
4. The application passes the URI to Guzzle, which transmits it to the `cURL` or `StreamHandler`.
5. The transport layer performs its own parsing, percent-decoding, or IDN resolution on the provided hostname.
6. The transport layer initiates a connection to the resolved, internal target, bypassing the initial application-level validation.
7. The application receives and potentially exposes the response content from the internal service, completing an SSRF attack.

## Impact

Successful exploitation allows attackers to interact with internal services or private network infrastructure that should be inaccessible from the outside. This can lead to unauthorized access to internal APIs, administrative interfaces, or sensitive data. While the vulnerability does not directly provide remote code execution, it serves as a critical primitive for SSRF attacks. There is no evidence of widespread in-the-wild exploitation, but the ease of crafting non-canonical hostnames makes this a high-risk issue for services relying on Guzzle for third-party requests.

## Recommendation

1. Upgrade to Guzzle `7.15.2` or `8.0.1` immediately to receive the built-in host validation patches.
2. If patching is not possible, implement the recommended validation logic from the advisory before passing any hostnames to Guzzle, specifically ensuring that host components are printable ASCII and do not contain percent escapes, delimiters, or trailing dots.
3. Treat user-supplied URIs as untrusted; perform resolution and address-based checks rather than relying on hostname string comparisons.
4. Use dedicated, restricted network namespaces or firewalls to limit the reach of outgoing requests from the application environment.

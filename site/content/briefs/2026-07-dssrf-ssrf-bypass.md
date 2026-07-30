---
title: SSRF Protection Bypass in dssrf Library via URL Normalization
slug: 2026-07-dssrf-ssrf-bypass
description: The dssrf library version 1.0.3 contains an SSRF bypass vulnerability in the is_url_safe function caused by improper character removal before URL parsing, allowing attackers to access restricted internal resources.
date: "2026-07-30T21:29:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - validation-bypass
  - cve-2026-54722
products:
  - dssrf (<= 1.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The dssrf library version 1.0.3 is vulnerable to an SSRF bypass due to improper input sanitization.
    confidence_band: high
cves:
  - id: CVE-2026-54722
references:
  - https://github.com/advisories/GHSA-cg4g-m8jx-vjv2
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-54722
---

The dssrf library (v1.0.3) is vulnerable to a Server-Side Request Forgery (SSRF) bypass due to an insecure sanitization routine in the `is_url_safe` function. The function applies a `remove_at_symbol_in_string` helper to the input URL string before the URL is parsed by the standard `new URL()` constructor. This process strips the `@` symbol, which serves as a critical delimiter between the userinfo component and the hostname in a URI. 

By removing this delimiter, the resulting hostname is corrupted, causing the internal IP/hostname validation logic to fail to recognize restricted targets. An attacker can craft a URL using the `userinfo@internal-ip` pattern, which passes the validation logic but is interpreted correctly by downstream HTTP clients (e.g., got, axios) to make requests to internal services, such as cloud metadata endpoints (e.g., 169.254.169.254) or internal network infrastructure. This vulnerability is tracked as CVE-2026-54722 and affects all users of dssrf version 1.0.3 and earlier.

## Impact

Successful exploitation allows an attacker to bypass security controls designed to prevent requests to sensitive internal services. This can lead to unauthorized access to internal resources, potential exfiltration of sensitive data, or interactions with cloud metadata services (IMDS) which may contain credentials. The impact is significant for applications relying on dssrf for perimeter security in cloud-native environments.

## Recommendation

- Upgrade to dssrf version 1.0.4 or later immediately to patch the validation logic.
- If upgrading is not immediately feasible, modify the `is_url_safe` function to remove the `remove_at_symbol_in_string` call.
- Implement a check for userinfo components after URL parsing: ensure `parsed.username` and `parsed.password` are empty before proceeding with trust decisions.
- Review applications using dssrf for logs indicating outbound requests to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254) initiated by server-side processes.

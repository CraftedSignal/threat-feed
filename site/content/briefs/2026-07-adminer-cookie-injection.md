---
title: Adminer Cookie Injection Vulnerability via X-Forwarded-Prefix Header (CVE-2026-63771)
slug: 2026-07-adminer-cookie-injection
description: Adminer versions prior to 5.4.3 are vulnerable to a cookie injection flaw, which allows attackers to manipulate cookie attributes by injecting arbitrary values through the unsanitized X-Forwarded-Prefix HTTP header, enabling cross-origin authenticated requests and bypassing cookie security controls.
date: "2026-07-20T19:27:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - cookie-injection
  - cve
  - CWE-113
vendors:
  - vrana
products:
  - Adminer < 5.4.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Adminer before 5.4.3 contains a cookie injection vulnerability that allows attackers to manipulate cookie attributes by injecting arbitrary values through the unsanitized X-Forwarded-Prefix HTTP header used in Set-Cookie path attributes. Attackers can exploit a misconfigured reverse proxy to downgrade SameSite protection and enable cross-origin authenticated requests, bypassing cookie security controls.
    confidence_band: high
cves:
  - id: CVE-2026-63771
    cvss: 7.1
references:
  - https://github.com/vrana/adminer/issues/1298
  - https://github.com/vrana/adminer/releases#release-v5.4.3
  - https://github.com/vrana/adminer/security/advisories/GHSA-c533-9qwm-8w5h
  - https://www.vulncheck.com/advisories/adminer-cookie-injection-via-x-forwarded-prefix-header
rules:
  - title: Detect CVE-2026-63771 Exploitation Attempts via X-Forwarded-Prefix
    description: Detects exploitation attempts for CVE-2026-63771 by identifying HTTP requests with the X-Forwarded-Prefix header containing characters typically used for cookie injection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Adminer, a database management tool, is affected by a cookie injection vulnerability, identified as CVE-2026-63771, impacting versions before 5.4.3. This flaw stems from the tool's unsanitized use of the `X-Forwarded-Prefix` HTTP header when setting `Set-Cookie` path attributes. Attackers can exploit this by sending a specially crafted `X-Forwarded-Prefix` header, particularly when Adminer is deployed behind a misconfigured reverse proxy. Successful exploitation allows for the manipulation of cookie attributes, such as downgrading SameSite protection, which can lead to the enabling of cross-origin authenticated requests and bypassing critical cookie security controls. This can result in session hijacking or unauthorized access to the Adminer interface, compromising database management capabilities.

## Attack Chain

1. An attacker identifies an Adminer instance running behind a misconfigured reverse proxy.
2. The attacker sends an HTTP request to the Adminer instance, including a crafted `X-Forwarded-Prefix` HTTP header containing special characters (e.g., `;`, `%0d%0a`, `=`) intended for cookie attribute injection.
3. The misconfigured reverse proxy forwards this request, and Adminer processes the unsanitized `X-Forwarded-Prefix` header when generating a `Set-Cookie` response.
4. Adminer injects the attacker-supplied values from `X-Forwarded-Prefix` directly into the `Set-Cookie` path attributes of the HTTP response.
5. This injection allows the attacker to manipulate cookie attributes, such as downgrading SameSite protection or setting arbitrary cookie properties.
6. By successfully manipulating the `Set-Cookie` header, the attacker enables cross-origin authenticated requests that would normally be prevented by browser security policies.
7. The attacker then leverages this weakened cookie security to perform unauthorized actions as an authenticated user from a different origin, bypassing standard browser security controls (e.g., session hijacking, unauthorized database access).

## Impact

Successful exploitation of CVE-2026-63771 allows attackers to bypass critical cookie security controls, potentially leading to unauthorized access to the Adminer interface and the underlying databases it manages. This can result in session hijacking, data exposure, data tampering, or unauthorized administrative actions within the affected environment. While no specific victim counts or targeted sectors are mentioned, any organization using vulnerable Adminer versions behind a misconfigured reverse proxy is at risk of compromising their database management infrastructure.

## Recommendation

* Patch CVE-2026-63771 by updating Adminer to version 5.4.3 or newer immediately.
* Deploy the Sigma rule "Detect CVE-2026-63771 Exploitation Attempts via X-Forwarded-Prefix" to your SIEM and tune for your environment, focusing on webserver logs.
* Configure reverse proxies to properly sanitize or remove the `X-Forwarded-Prefix` header before forwarding requests to backend applications if it is not explicitly required.

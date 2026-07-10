---
title: Tesla Elixir HTTP Client Header Leak via Case-Sensitive Redirect Filtering (CVE-2026-48595)
slug: 2026-07-tesla-header-leak
description: A vulnerability in the `Tesla.Middleware.FollowRedirects` component of the `tesla` Elixir HTTP client library allows `Authorization` headers to be leaked during cross-origin redirects due to a case-sensitive comparison, enabling an attacker controlling a redirect destination to receive bearer tokens or other credentials from applications using `tesla` versions 0.6.0 through 1.18.2.
date: "2026-07-10T00:07:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - exfiltration
  - vulnerability
  - elixir
  - http-client
products:
  - tesla (>= 0.6.0, < 1.18.3)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This enables an attacker controlling a redirect destination to receive bearer tokens or other credentials.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: sensitive credentials like bearer tokens can be inadvertently leaked to the attacker
    confidence_band: high
cves:
  - id: CVE-2026-48595
    epss: 0.00396
references:
  - https://github.com/advisories/GHSA-9m9w-gxf7-rh8m
  - https://github.com/elixir-tesla/tesla/commit/2d937d5813d7cda5cd726f41824985fb655c920f
  - https://github.com/elixir-tesla/tesla/commit/db963dba67651b9abd1fc420a1d9679cf6efe182
---

A high-severity vulnerability, CVE-2026-48595, has been identified in the `tesla` Elixir HTTP client library, specifically within its `Tesla.Middleware.FollowRedirects` component. This flaw impacts versions 0.6.0 up to, but not including, 1.18.3. The middleware is designed to strip sensitive `Authorization` headers when following cross-origin redirects to prevent credential leakage. However, its internal filter performs a case-sensitive comparison against a lowercase string `"authorization"`. Because `tesla` preserves header keys exactly as supplied, applications using the RFC 7235 canonical casing (`"Authorization"`) bypass this filter entirely. Consequently, if an application sends a request with an `Authorization` header using canonical casing and is redirected to an attacker-controlled origin, sensitive credentials like bearer tokens can be inadvertently leaked to the attacker. This poses a significant risk to applications relying on `tesla` for secure HTTP communications.

## Attack Chain

1. An attacker establishes control over a web server or service capable of issuing HTTP `302` redirects to an arbitrary, attacker-controlled domain (e.g., a malicious server, a redirect-open service, or a compromised upstream server).
2. A victim application, using the `tesla` Elixir HTTP client library (version 0.6.0 through 1.18.2) with `Tesla.Middleware.FollowRedirects` enabled, constructs an outbound HTTP request.
3. The victim application includes an `Authorization` header with canonical casing (e.g., `{"Authorization", "Bearer <token>"}`) for authentication in its request.
4. The victim application sends its request to an endpoint, which the attacker can influence to issue an HTTP `302` (or similar redirect status code) pointing to the attacker-controlled domain.
5. The `Tesla.Middleware.FollowRedirects` component within the victim application attempts to filter sensitive headers before automatically following the redirect.
6. Due to a case-sensitive comparison logic (`"authorization"` vs. `"Authorization"`), the middleware fails to identify and strip the canonical `Authorization` header from the outgoing request.
7. The `tesla` client follows the redirect and inadvertently includes the sensitive `Authorization` header, complete with its bearer token or other credentials, in the request to the attacker-controlled domain, leading to credential theft.

## Impact

The vulnerability carries a high severity (CVSS v4.0: 8.2). Any application utilizing `tesla` versions 0.6.0 through 1.18.2 with `Tesla.Middleware.FollowRedirects` and supplying non-lowercase `Authorization` headers is at risk. Successful exploitation results in the leakage of sensitive credentials, such as bearer tokens, to an attacker-controlled endpoint. This can lead to unauthorized access to systems or data, session hijacking, and further compromise of the victim's environment, directly impacting the confidentiality and integrity of affected applications and their users.

## Recommendation

* Prioritize upgrading the `tesla` Elixir HTTP client library to version 1.18.3 or later immediately to remediate CVE-2026-48595.
* If immediate patching is not possible, implement the recommended workaround by normalizing all `Authorization` header keys to lowercase (e.g., `"authorization"`) before passing them to `tesla` via `Tesla.put_header/3` or `Tesla.Middleware.Headers`.
* Review application code for the usage of `Tesla.Middleware.FollowRedirects` and how `Authorization` headers are set to identify potentially vulnerable instances.

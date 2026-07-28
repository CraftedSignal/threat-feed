---
title: OAuth2::Client Redirection Vulnerability Leaks Bearer Tokens
slug: 2026-07-oauth2-client-redirect-leak
description: The `OAuth2::Client` in the `oauth2` Ruby gem is vulnerable to credential disclosure and Server-Side Request Forgery (SSRF) due to improper handling of protocol-relative redirect URLs, allowing an attacker to steal bearer tokens and access internal network resources.
date: "2026-07-28T16:33:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - oauth2
  - ruby
  - vulnerability
  - credential-disclosure
  - ssrf
  - redirect
  - ghsa
vendors:
  - ruby-oauth
products:
  - oauth2 (>= 0.4.0, <= 2.0.21)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: When an application uses `OAuth2::Client` ... and the configured authorization server returns a redirect whose `Location` header is a protocol-relative URI ... `OAuth2::Client#request` resolves the redirect with `response.response.env.url.merge(location)`.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'Cross-origin credential disclosure: The connection-scoped `Authorization: Bearer <token>` header attached by `OAuth2::AccessToken#configure_authentication!` is sent to the attacker host on the very next request, with no second user interaction.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: ""
    evidence: SSRF from the application server. The OAuth2 client follows the redirect on behalf of the application, so the host that ultimately receives the request is one the attacker chooses — useful for hitting internal addresses (`//169.254.169.254/...`, `//127.0.0.1:.../...`) that the application server can reach but the attacker cannot.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-pp92-crg2-gfv9
iocs:
  - type: domain
    value: attacker.example.test
  - type: url
    value: http://idp.example.test
  - type: ip
    value: 169.254.169.254
ioc_counts:
  domain: 1
  ip: 1
  url: 1
---

A critical vulnerability (CVE-2026-54603) exists in the `OAuth2::Client` component of the `oauth2` Ruby gem, affecting versions from 0.4.0 up to and including 2.0.21. This flaw stems from improper resolution of protocol-relative redirect URIs within the `OAuth2::Client#request` method. When an OAuth2 application makes a request and its configured Identity Provider (IdP) or an open-redirect vulnerability can be influenced to return a 30x redirect with a `Location` header such as `//attacker.example/leak`, the `OAuth2::Client` incorrectly merges this URI. As a result, the subsequent request, including the `Authorization: Bearer <access-token>` header, is redirected to the attacker-controlled host instead of remaining with the trusted IdP. This vulnerability leads to both cross-origin credential disclosure and potential Server-Side Request Forgery (SSRF) from the application server, allowing attackers to steal sensitive tokens and probe internal networks.

## Attack Chain

1. An application, using `OAuth2::AccessToken` via `OAuth2::Client`, initiates a request to a trusted Identity Provider (IdP) or resource server, including an `Authorization: Bearer <access-token>` header.
2. An attacker, by exploiting an open redirect vulnerability on the IdP, configuring a malicious tenant in a multi-tenant setup, or through a network compromise, causes the IdP to issue an HTTP 30x redirect response.
3. The crafted redirect response's `Location` header contains a protocol-relative URI pointing to an attacker-controlled host (e.g., `//attacker.example/leak`).
4. The `OAuth2::Client#request` method attempts to resolve this redirect by calling `response.response.env.url.merge(location)`. Per RFC 3986 §5.2, `URI#merge` interprets the protocol-relative URI as a network-path reference, which overrides the authority (scheme and host) of the base URL.
5. The library then recursively re-invokes `request(verb, full_location, req_opts)` using the newly resolved attacker-controlled URL. Crucially, the `req_opts` dictionary, containing the original request headers, is passed verbatim.
6. The `Authorization: Bearer <access-token>` header, initially set by `OAuth2::AccessToken#configure_authentication!`, is preserved and transmitted in the request to the attacker's host.
7. The attacker-controlled server receives the application's bearer token, achieving immediate cross-origin credential disclosure without further user interaction.
8. Alternatively, if the `Location` URI specifies an internal network address (e.g., `//169.254.169.254/`), the application server acts as a Server-Side Request Forgery (SSRF) proxy, allowing the attacker to interact with internal resources.

## Impact

Successful exploitation of this vulnerability results in two primary impacts:
1. **Cross-origin credential disclosure:** The immediate consequence is the theft of `Authorization: Bearer` tokens. Any application utilizing the vulnerable `oauth2` gem to communicate with an IdP susceptible to such redirection risks having its access tokens exfiltrated to an attacker-controlled server. This can lead to unauthorized access to user data or resources that the stolen token grants access to.
2. **Server-Side Request Forgery (SSRF):** The ability to redirect the application's requests to an arbitrary host also enables SSRF. Attackers can leverage this to force the application server to make requests to internal network services, cloud metadata endpoints (e.g., `169.254.169.254`), or other restricted resources that are typically inaccessible from the internet. This could facilitate reconnaissance, lateral movement, or further exploitation within an organization's internal infrastructure. Given the widespread use of OAuth2 in modern applications, the potential number of affected services and organizations is substantial across all sectors.

## Recommendation

* Upgrade the `oauth2` gem to version `2.0.22` or later immediately to address CVE-2026-54603.
* Apply the suggested patch logic to `OAuth2::Client#request` as an interim measure if immediate gem upgrade is not possible. This involves forcing protocol-relative `Location` values to be interpreted as relative paths by prepending `./` before `URI#merge`.
* Developers should review their Identity Provider (IdP) and resource server configurations to ensure they do not expose open redirect vulnerabilities that could be abused to supply malicious `Location` headers.
* Implement defense-in-depth measures to strip credential-bearing headers (like `Authorization`) from requests when a redirect crosses origin boundaries, similar to how robust HTTP clients handle such scenarios.

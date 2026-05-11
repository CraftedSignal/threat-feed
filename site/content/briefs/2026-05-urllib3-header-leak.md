---
title: urllib3 Sensitive Header Leak in Low-Level Redirects (CVE-2026-44431)
slug: 2026-05-urllib3-header-leak
description: Sensitive headers (`Authorization`, `Cookie`, and `Proxy-Authorization`) are forwarded across origins in proxied low-level redirects when using `HTTPConnection.urlopen()` instances created via `ProxyManager.connection_from_url()` in urllib3 versions before 2.7.0, potentially exposing credentials to unintended third parties; upgrade to version 2.7.0 or later to remediate this issue.
date: "2026-05-11T14:53:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - urllib3
  - header-leak
  - vulnerability
vendors:
  - Python Packaging Index (PyPI)
products:
  - urllib3 (< 2.7.0)
references:
  - https://github.com/advisories/GHSA-qccp-gfcp-xxvc
  - CVE-2026-44431
rules:
  - title: Detect urllib3 Low-Level API Cross-Origin Redirect with Sensitive Headers
    description: Detects applications using urllib3's low-level API to follow cross-origin redirects without proper header stripping, potentially indicating exploitation of CVE-2026-44431.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect urllib3 HTTPConnection.urlopen with assert_same_host=False
    description: Detects calls to HTTPConnection.urlopen with assert_same_host=False, which is a prerequisite for CVE-2026-44431 exploitation.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The urllib3 library, a popular Python HTTP client, is vulnerable to sensitive header leakage (CVE-2026-44431) when handling cross-origin redirects in its low-level API. Specifically, when applications use `HTTPConnection.urlopen()` instances created via `ProxyManager.connection_from_url()` and allow cross-origin redirects, sensitive headers like `Authorization`, `Cookie`, and `Proxy-Authorization` are inadvertently forwarded to the redirect destination. This behavior can expose sensitive credentials to unintended third-party servers. This vulnerability affects urllib3 versions before 2.7.0. Defenders should prioritize upgrading urllib3 to version 2.7.0 or later to mitigate this risk and ensure proper handling of sensitive headers during redirects. If immediate upgrade is not feasible, applications should avoid using the vulnerable low-level redirect flow for cross-origin redirects and consider switching to `ProxyManager.request()` instead.

## Attack Chain

1. The attacker controls a malicious website or compromises an existing one.
2. A user's application (using a vulnerable urllib3 version) initiates an HTTP request to a controlled domain.
3. The attacker's server responds with an HTTP 302 redirect to a different, attacker-controlled origin.
4. The application, using `ProxyManager.connection_from_url().urlopen(..., assert_same_host=False)`, follows the redirect.
5. Due to the vulnerability, the application inappropriately forwards sensitive headers (Authorization, Cookie, Proxy-Authorization) along with the redirected request.
6. The attacker's server receives the forwarded request containing the sensitive headers, potentially including authentication tokens or session IDs.
7. The attacker captures and logs these sensitive headers.
8. The attacker uses the captured credentials to impersonate the user or gain unauthorized access to protected resources.

## Impact

Successful exploitation of this vulnerability (CVE-2026-44431) can lead to the exposure of sensitive user credentials, including authentication tokens and session cookies. The impact ranges from account compromise to unauthorized access to sensitive data and resources. The number of potential victims depends on the adoption rate of vulnerable urllib3 versions and the frequency with which applications utilize the susceptible low-level redirect flow. Applications that handle authentication or authorization via HTTP headers are particularly at risk.

## Recommendation

*   Upgrade to urllib3 version 2.7.0 or later to remediate the vulnerability (CVE-2026-44431), where sensitive headers are stripped from redirects followed by `HTTPConnection`.
*   If upgrading is not immediately possible, avoid using the low-level redirect flow (`ProxyManager.connection_from_url().urlopen(..., assert_same_host=False)`) for cross-origin redirects.
*   Consider switching to `ProxyManager.request()` if appropriate for your use case, as this high-level API strips sensitive headers during redirects by default.
*   Deploy the Sigma rule "Detect urllib3 Low-Level API Cross-Origin Redirect with Sensitive Headers" to detect potential exploitation attempts by monitoring for the vulnerable code pattern.

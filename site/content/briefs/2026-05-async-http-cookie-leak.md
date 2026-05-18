---
title: async-http-client Cookie Header Leak on Cross-Origin Redirect
slug: 2026-05-async-http-cookie-leak
description: The async-http-client library leaks `Cookie` headers to cross-origin redirect targets due to missing header stripping in `Redirect30xInterceptor.java`, potentially exposing sensitive information to malicious third parties.
date: "2026-05-18T16:44:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cookie
  - header
  - redirect
  - vulnerability
  - ghsa
  - CVE-2026-45300
vendors:
  - AsyncHttpClient
products:
  - async-http-client (>= 3.0.0.Beta1, < 3.0.10)
  - async-http-client (>= 2.0.0, < 2.15.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-fmxf-pm6p-7xgm
  - https://github.com/AsyncHttpClient/async-http-client/commit/3b0e3e9e
rules:
  - title: Detect AsyncHttpClient Cookie Leak via Redirect
    description: Detects CVE-2026-45300 — Detects potential cookie leakage during cross-origin redirects, indicated by a redirect followed by a request containing cookie data to a different domain.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-45300
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect AsyncHttpClient Auth Header Removal
    description: Detects AsyncHttpClient removing Authorization headers.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - webserver
rules_count: 2
---

The async-http-client library is vulnerable to leaking `Cookie` headers to cross-origin redirect targets. Specifically, when following a redirect across a security boundary (different origin, or HTTPS→HTTP downgrade), the `propagatedHeaders()` method in `Redirect30xInterceptor.java` does not strip the `Cookie` header, leading to potential exposure of session cookies, CSRF tokens, and API keys. This vulnerability exists in versions of `async-http-client` between 3.0.0.Beta1 and 3.0.10, as well as between 2.0.0 and 2.15.0. Attackers can exploit this by crafting malicious redirects that forward sensitive cookie data to attacker-controlled destinations, potentially leading to session hijacking and data theft. This matters for defenders as it exposes applications using the affected library to significant security risks if they rely on redirects with cookies for authentication or authorization. The vulnerability is fixed in versions 3.0.10 and 2.15.0. CVE-2026-45300 has been assigned to this issue.

## Attack Chain

1. The victim's application initiates an HTTP request to a trusted API endpoint.
2. The trusted API endpoint responds with a 302 redirect to a malicious URL (e.g., `https://evil.com`).
3. The `Redirect30xInterceptor.java` class in `async-http-client` processes the redirect.
4. The `propagatedHeaders()` method is called to determine which headers to forward.
5. Due to the vulnerability, the `Cookie` header is not stripped, unlike `Authorization` and `Proxy-Authorization`.
6. The `async-http-client` library forwards the original request, including the `Cookie` header, to the malicious URL.
7. The attacker-controlled server at `evil.com` receives the leaked `Cookie` header.
8. The attacker can then extract sensitive information from the `Cookie` header, such as session IDs, CSRF tokens, or API keys for malicious purposes.

## Impact

Successful exploitation of this vulnerability can lead to:
- **Session hijacking**: Attackers can use leaked session cookies to impersonate legitimate users.
- **CSRF token theft**: Attackers can steal CSRF tokens carried in cookies to perform unauthorized actions on behalf of the user.
- **API key theft**: Attackers can obtain API keys stored in cookies to access sensitive resources.
- **Privacy breaches**: Tracking identifiers leak to third-party origins, compromising user privacy.

Attack scenarios include open-redirects in trusted API endpoints, compromised CDNs or API gateways injecting redirects, and man-in-the-middle attacks on plaintext hops in the redirect chain.  Organizations using vulnerable versions of `async-http-client` are at risk.

## Recommendation

*   Upgrade `async-http-client` to version 3.0.10 or 2.15.0 to patch the vulnerability as described in the fix details.
*   Deploy the Sigma rule "Detect AsyncHttpClient Cookie Leak via Redirect" to identify potential exploitation attempts in web server logs.
*   Review and audit application code to ensure proper handling of redirects and cookie security.
*   Monitor network traffic for suspicious redirects to external domains and unexpected cookie transfers.

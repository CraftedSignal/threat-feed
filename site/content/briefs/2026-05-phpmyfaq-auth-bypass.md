---
title: phpMyFAQ Authentication Bypass via Empty API Token (CVE-2026-35672)
slug: 2026-05-phpmyfaq-auth-bypass
description: phpMyFAQ before 4.1.3 contains an authentication bypass vulnerability in API v4.0, allowing unauthenticated users to create and modify FAQ entries by sending an empty x-pmf-token header, tracked as CVE-2026-35672.
date: "2026-05-28T16:18:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - authentication bypass
  - web application
  - phpMyFAQ
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35672
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35672
  - https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-gp95-j463-vv28
  - https://www.vulncheck.com/advisories/phpmyfaq-authentication-bypass-via-empty-api-token
rules:
  - title: Detect phpMyFAQ Authentication Bypass via Empty Token Header
    description: Detects CVE-2026-35672 exploitation — phpMyFAQ authentication bypass attempts by sending an empty x-pmf-token header to vulnerable API endpoints.
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

phpMyFAQ, a PHP-based FAQ management system, is vulnerable to an authentication bypass (CVE-2026-35672) affecting versions prior to 4.1.3. This flaw resides within the API v4.0 implementation. The default configuration uses an empty `api.apiClientToken`, which permits unauthenticated users to bypass token validation. An attacker can leverage this by sending HTTP POST requests with an empty `x-pmf-token` header to vulnerable API endpoints, effectively gaining the ability to create and modify FAQ content without proper authorization. This vulnerability was publicly disclosed on May 28, 2026. Exploitation can lead to unauthorized modification of website content, potentially injecting malicious scripts or misinformation.

## Attack Chain

1.  Attacker identifies a phpMyFAQ instance running a version prior to 4.1.3.
2.  Attacker crafts an HTTP POST request targeting one of the vulnerable API endpoints: `/api/v4.0/faq/create`, `/api/v4.0/category`, or `/api/v4.0/question`.
3.  The POST request includes an `x-pmf-token` header with an empty value.
4.  The phpMyFAQ server, due to the default empty `api.apiClientToken` configuration, fails to properly validate the token.
5.  The attacker includes malicious content within the POST request body, such as crafted FAQ entries or category modifications.
6.  The server processes the POST request, creating or modifying FAQ content based on the attacker's input without authentication.
7.  The attacker's injected content is now visible on the phpMyFAQ website, potentially leading to further compromise or misinformation.

## Impact

Successful exploitation of this vulnerability (CVE-2026-35672) allows unauthenticated attackers to modify FAQ content, potentially injecting malicious scripts or misinformation into the phpMyFAQ instance. This can lead to website defacement, cross-site scripting (XSS) attacks against website visitors, or the spread of false information, damaging the reputation of the organization hosting the FAQ. The impact is high due to the ease of exploitation and the potential for widespread content manipulation.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.3 or later to patch the authentication bypass vulnerability (CVE-2026-35672).
*   Deploy the Sigma rule `Detect phpMyFAQ Authentication Bypass via Empty Token Header` to identify exploitation attempts targeting the vulnerable API endpoints.
*   Monitor web server logs for POST requests to `/api/v4.0/faq/create`, `/api/v4.0/category`, and `/api/v4.0/question` with empty `x-pmf-token` headers.

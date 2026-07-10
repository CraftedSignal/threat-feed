---
title: WWBN AVideo CORS Vulnerability (CVE-2026-41057)
slug: 2024-01-wwbn-avideo-cors
description: WWBN AVideo versions 29.0 and below are vulnerable to cross-origin credentialed requests to API endpoints due to an incomplete CORS origin validation fix, potentially exposing sensitive user data.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - CVE-2026-41057
  - CORS
  - AVideo
  - webserver
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41057
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41057
rules:
  - title: AVideo API Access with Suspicious Origin Header
    description: Detects access to AVideo API endpoints with a non-empty Origin header, which could indicate a CORS exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: AVideo API POST Request with Credentialed Origin
    description: Detects POST requests to AVideo API endpoints with a credentialed `Origin` header which may indicate potential exploitation of CORS vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is susceptible to a CORS vulnerability (CVE-2026-41057) in versions 29.0 and below. The vulnerability stems from an incomplete fix for CORS origin validation. Specifically, two code paths, `plugin/API/router.php` and `allowOrigin(true)` called by `get.json.php` and `set.json.php`, reflect arbitrary `Origin` headers, allowing credentials for all `/api/*` endpoints. This flaw enables attackers to bypass CORS restrictions and make cross-origin credentialed requests. A fix has been implemented in commit 5e2b897ccac61eb6daca2dee4a6be3c4c2d93e13. This vulnerability could lead to the exposure of sensitive information, including user PII, email addresses, admin status, and session-sensitive data. Defenders should prioritize patching affected AVideo instances.

## Attack Chain

1. Attacker identifies an AVideo instance running version 29.0 or below.
2. Attacker crafts a malicious webpage containing JavaScript code designed to make cross-origin requests to the vulnerable AVideo instance's `/api/*` endpoints.
3. The malicious webpage sets the `Origin` header to an arbitrary value.
4. Due to the incomplete CORS validation in `plugin/API/router.php`, the server reflects the arbitrary origin.
5. Alternatively, the malicious webpage triggers `get.json.php` or `set.json.php`, which call `allowOrigin(true)` and reflect the arbitrary origin with `Access-Control-Allow-Credentials: true`.
6. The attacker's JavaScript code sends a credentialed request (e.g., including cookies) to the `/api/*` endpoint.
7. The AVideo server processes the request and returns an authenticated response containing user PII, email, admin status, and session-sensitive data.
8. The attacker's malicious webpage extracts and exfiltrates the sensitive data from the response.

## Impact

Successful exploitation of CVE-2026-41057 allows attackers to bypass CORS restrictions and access sensitive information from vulnerable AVideo instances. This includes user PII, email addresses, admin status, and session-sensitive data. The impact could range from unauthorized access to user accounts to complete compromise of the AVideo platform, depending on the specific API endpoint targeted and the permissions of the compromised user. The number of victims is dependent on the number of vulnerable AVideo instances exposed to the internet.

## Recommendation

*   Apply the patch from commit `5e2b897ccac61eb6daca2dee4a6be3c4c2d93e13` to remediate CVE-2026-41057.
*   Deploy the Sigma rules provided to detect attempts to exploit this CORS vulnerability within web server logs.
*   Monitor web server logs for requests to `/api/*` endpoints with unusual or unexpected `Origin` headers.
*   Implement proper CORS validation on all AVideo instances, ensuring that only trusted origins are allowed to access sensitive API endpoints.

---
title: WWBN AVideo Cross-Origin Request Vulnerability (CVE-2026-41056)
slug: 2024-01-avideo-xss
description: WWBN AVideo versions 29.0 and below are vulnerable to cross-origin request attacks (CVE-2026-41056) due to improper handling of Origin headers and session cookies, allowing unauthorized access to user data and system modifications.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - avideo
  - cors
  - credential-access
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Web Browsers
cves:
  - id: CVE-2026-41056
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41056
rules:
  - title: Detect Suspicious Origin Header to AVideo API Endpoints
    description: Detects potentially malicious requests to AVideo API endpoints with unusual Origin headers, indicating a possible CORS vulnerability exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: AVideo API Endpoint Access with Credentials
    description: Detects access to AVideo API endpoints where credentials are being passed in the request. This can be useful for detecting possible exploitation of CVE-2026-41056.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is vulnerable to a cross-origin request vulnerability (CVE-2026-41056) in versions 29.0 and below. The vulnerability stems from the `allowOrigin($allowAll=true)` function located in `objects/functions.php`, which improperly reflects arbitrary `Origin` headers in the `Access-Control-Allow-Origin` response header and also sets `Access-Control-Allow-Credentials: true`. This function is called by the `plugin/API/get.json.php` and `plugin/API/set.json.php` API endpoints. The combination of this behavior with the application's use of `SameSite=None` session cookies allows attackers to make credentialed cross-origin requests. This can lead to the theft of sensitive user information (PII), access to livestream keys, and the ability to perform unauthorized actions on behalf of legitimate users. The vulnerability was patched in commit caf705f38eae0ccfac4c3af1587781355d24495e.

## Attack Chain

1.  Attacker crafts a malicious website with JavaScript code designed to make cross-origin requests to a vulnerable AVideo instance.
2.  Victim visits the attacker's malicious website in a browser where they are also authenticated to the AVideo application due to the `SameSite=None` cookie policy.
3.  The malicious JavaScript initiates an HTTP request to `plugin/API/get.json.php` or `plugin/API/set.json.php` on the AVideo server, including the victim's session cookie.
4.  The AVideo server, due to the vulnerable `allowOrigin` function, reflects the attacker's origin in the `Access-Control-Allow-Origin` header and sets `Access-Control-Allow-Credentials: true`.
5.  The victim's browser, trusting the response due to the permissive CORS policy, allows the JavaScript code to read the response from the AVideo server.
6.  The attacker's JavaScript extracts sensitive information from the API response, such as user PII or livestream keys.
7.  The attacker exfiltrates the stolen information to a server under their control.
8.  The attacker leverages stolen credentials or keys to access user accounts, modify content, or conduct unauthorized live streams.

## Impact

Successful exploitation of CVE-2026-41056 can result in the compromise of user accounts, theft of sensitive personal information, and unauthorized access to livestreaming functionality within AVideo. There is no specific victim count available, but all installations of AVideo version 29.0 and below are vulnerable. The impact could range from defacement of video content to full account takeover and potential financial losses due to unauthorized livestreaming.

## Recommendation

*   Immediately upgrade all AVideo instances to a version containing the fix from commit caf705f38eae0ccfac4c3af1587781355d24495e.
*   Monitor web server logs for suspicious `Origin` headers targeting the `/plugin/API/get.json.php` and `/plugin/API/set.json.php` endpoints using the Sigma rules provided.
*   Implement a Web Application Firewall (WAF) rule to reject requests with unusual or unexpected `Origin` headers to mitigate potential exploitation attempts of CVE-2026-41056.
*   Review and harden the AVideo application's session management and CORS policies to prevent future cross-origin vulnerabilities.

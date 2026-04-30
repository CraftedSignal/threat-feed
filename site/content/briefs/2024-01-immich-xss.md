---
title: Immich Stored XSS Vulnerability in 360° Panorama Viewer (CVE-2026-35455)
slug: 2024-01-immich-xss
description: A stored cross-site scripting (XSS) vulnerability in Immich versions before 2.7.0 allows authenticated users to inject arbitrary JavaScript via crafted equirectangular images, leading to session hijacking, data exfiltration, and unauthorized access.
date: "2026-04-08T19:25:24Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - immich
  - xss
  - cve-2026-35455
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35455
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35455
rules:
  - title: Detect Suspicious Immich Panorama Requests
    description: Detects potential exploitation of the Immich XSS vulnerability (CVE-2026-35455) by identifying suspicious requests to the panorama viewer with potential XSS payloads in the URL.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Possible XSS Attempts via URI
    description: Detects possible XSS attempts via requests with javascript in the URI
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Immich, a self-hosted photo and video management solution, is vulnerable to a stored Cross-Site Scripting (XSS) attack.  Specifically, versions prior to 2.7.0 are susceptible. An authenticated attacker can exploit the 360° panorama viewer by uploading a specially crafted equirectangular image that contains malicious text. When another user views the panorama with the OCR overlay enabled, the injected text is extracted via OCR and rendered by the panorama viewer without sanitization. This leads to arbitrary JavaScript execution within the victim's browser. The vulnerability, identified as CVE-2026-35455, poses a significant risk, potentially leading to session hijacking (via persistent API key creation), private photo exfiltration, and unauthorized access to sensitive data like GPS location history and face biometric data. Users are advised to upgrade to version 2.7.0 or later to mitigate this risk.

## Attack Chain

1. An attacker authenticates to an Immich instance with a valid user account.
2. The attacker crafts an equirectangular image containing malicious JavaScript code embedded within the text.
3. The attacker uploads the crafted image to the Immich server through the web interface.
4. The attacker shares or otherwise causes another user to view the uploaded panorama image.
5. The victim views the panorama image with the OCR overlay feature enabled.
6. The Immich server processes the image, and the OCR engine extracts the malicious JavaScript from the image.
7. The panorama viewer renders the OCR output via `innerHTML` without proper sanitization.
8. The malicious JavaScript executes within the victim's browser session, allowing the attacker to perform actions such as session hijacking, data exfiltration, or unauthorized data access.

## Impact

Successful exploitation of this XSS vulnerability (CVE-2026-35455) in Immich can lead to severe consequences. An attacker can hijack user sessions by creating persistent API keys, allowing them to impersonate the victim. Furthermore, they can exfiltrate private photos and gain unauthorized access to sensitive information such as GPS location history and face biometric data stored within the Immich instance. The number of potential victims corresponds to the number of users on a vulnerable Immich instance. Given the self-hosted nature of Immich, the impact is largely dependent on the type and sensitivity of data stored within affected deployments.

## Recommendation

*   Upgrade Immich to version 2.7.0 or later to patch the CVE-2026-35455 vulnerability.
*   Implement input validation and sanitization for user-uploaded content, particularly images, to prevent XSS attacks. Focus on `webserver` logs for unusual POST requests.
*   Deploy the Sigma rule `Detect Suspicious Immich Panorama Requests` to identify potential exploitation attempts based on unusual URL parameters indicative of crafted panorama requests.
*   Monitor `webserver` logs for HTTP requests containing suspicious JavaScript payloads within the URL, which may indicate XSS attempts.

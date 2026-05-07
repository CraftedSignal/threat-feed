---
title: DivvyDrive Cross-Site Scripting (XSS) Vulnerability (CVE-2026-6002)
slug: 2026-05-divvy-xss
description: DivvyDrive versions 4.8.2.9 before 4.8.3.2 are susceptible to cross-site scripting (XSS) due to improper neutralization of script-related HTML tags, potentially allowing an attacker to inject malicious scripts.
date: "2026-05-07T13:16:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - cve-2026-6002
  - web-application
vendors:
  - DivvyDrive Information Technologies Inc.
products:
  - DivvyDrive (>= 4.8.2.9, < 4.8.3.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6002
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6002
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0182
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious URI containing script tag
    description: Detects suspicious URI requests containing script tags, indicative of potential XSS attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious URI containing encoded script tag
    description: Detects suspicious URI requests containing encoded script tags, indicative of potential XSS attacks.
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

DivvyDrive versions 4.8.2.9 before 4.8.3.2 are vulnerable to cross-site scripting (XSS) due to improper neutralization of script-related HTML tags. This vulnerability, identified as CVE-2026-6002, can be exploited by an attacker to inject arbitrary JavaScript code into the context of a user's browser session. Successful exploitation could lead to session hijacking, defacement of the web page, or redirection of the user to malicious websites. The vulnerability was reported by the Computer Emergency Response Team of the Republic of Turkey.

## Attack Chain

1. An attacker crafts a malicious URL containing a script-related HTML tag (e.g., `<script>`) within a parameter value.
2. A victim user clicks the malicious URL or is redirected to a page containing the crafted URL.
3. The DivvyDrive application fails to properly sanitize the input, embedding the attacker's script into the HTML output.
4. The victim's browser executes the injected script, as it is rendered as part of the trusted web page.
5. The malicious script steals the victim's session cookies or other sensitive information.
6. The attacker uses the stolen cookies to impersonate the victim and gain unauthorized access to their account.
7. The attacker modifies the victim's data or performs actions on their behalf, potentially causing damage to their data.

## Impact

Successful exploitation of this XSS vulnerability can lead to account compromise, data theft, and defacement of the DivvyDrive application. An attacker can steal session cookies, allowing them to impersonate legitimate users and perform unauthorized actions. The severity of the impact depends on the privileges of the compromised user and the extent to which the attacker can manipulate the application. The vulnerability affects versions 4.8.2.9 before 4.8.3.2 of DivvyDrive.

## Recommendation

*   Upgrade DivvyDrive to version 4.8.3.2 or later to patch CVE-2026-6002.
*   Implement proper input validation and output encoding to prevent XSS attacks in DivvyDrive.
*   Deploy the Sigma rule "Detect Suspicious URI containing script tag" to identify potential XSS attempts in web server logs.
*   Monitor web server logs for suspicious URI requests containing script tags or other potentially malicious content using the provided IOC (email address).

---
title: LiteSpeed Cache Plugin Stored XSS Vulnerability (CVE-2026-3375)
slug: 2026-05-litespeed-cache-xss
description: The LiteSpeed Cache plugin for WordPress is vulnerable to stored Cross-Site Scripting (XSS) via the /wp-json/litespeed/v1/notify_ccss and /wp-json/litespeed/v1/notify_ucss REST API endpoints, affecting versions up to 7.7, allowing unauthenticated attackers to inject arbitrary JavaScript into CCSS/UCSS content by bypassing IP-based access controls.
date: "2026-05-27T08:18:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - xss
  - wordpress
  - litespeed
  - plugin
vendors:
  - LiteSpeed
products:
  - LiteSpeed Cache plugin for WordPress
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-3375
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3375
  - CVE-2026-3375
rules:
  - title: Detect CVE-2026-3375 Exploitation via LiteSpeed Cache REST API
    description: Detects CVE-2026-3375 exploitation — POST requests to /wp-json/litespeed/v1/notify_ccss or /wp-json/litespeed/v1/notify_ucss with potentially malicious CSS content.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 1
---

The LiteSpeed Cache plugin for WordPress, a popular performance optimization tool, contains a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-3375) in versions up to and including 7.7. The vulnerability exists within the /wp-json/litespeed/v1/notify_ccss and /wp-json/litespeed/v1/notify_ucss REST API endpoints. These endpoints are designed to receive CSS content from QUIC.cloud callback notifications. However, the plugin fails to properly sanitize this content before storing it to disk. Consequently, when the stored CSS is rendered inline during frontend page loads, it is not output-escaped, creating an opportunity for malicious code injection. This IP-based access control that protects these endpoints can be bypassed when the WordPress site is deployed behind a reverse proxy, load balancer, or CDN with certain configurations. Exploitation could lead to arbitrary JavaScript execution within the context of a user's browser.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using a vulnerable version of the LiteSpeed Cache plugin (<= 7.7) behind a reverse proxy.
2. The attacker crafts a malicious payload containing JavaScript code embedded within CSS syntax.
3. The attacker bypasses the IP-based access control, possibly by spoofing or manipulating headers related to the reverse proxy.
4. The attacker sends a POST request to either the /wp-json/litespeed/v1/notify_ccss or /wp-json/litespeed/v1/notify_ucss endpoint with the malicious CSS payload.
5. The vulnerable endpoint stores the unsanitized CSS content to disk.
6. A user visits a page on the compromised WordPress site.
7. The stored CSS, including the injected JavaScript, is rendered inline within the page's HTML.
8. The user's browser executes the attacker-controlled JavaScript, leading to XSS.

## Impact

Successful exploitation of this XSS vulnerability (CVE-2026-3375) can lead to a range of detrimental outcomes. An attacker could inject malicious scripts that steal user session cookies, redirect users to phishing sites, deface the website, or perform other unauthorized actions on behalf of the user. The vulnerability affects all sites using the LiteSpeed Cache plugin for WordPress with versions up to and including 7.7 and is deployed behind a reverse proxy, load balancer, or CDN.

## Recommendation

*   Upgrade the LiteSpeed Cache plugin for WordPress to a version greater than 7.7 to patch CVE-2026-3375.
*   Implement robust input validation and output encoding mechanisms for the /wp-json/litespeed/v1/notify_ccss and /wp-json/litespeed/v1/notify_ucss REST API endpoints.
*   Deploy the Sigma rule to detect potential exploitation attempts by monitoring POST requests to the vulnerable endpoints (see rule: "Detect CVE-2026-3375 Exploitation via LiteSpeed Cache REST API").
*   Review the reverse proxy, load balancer, or CDN configuration to ensure proper IP-based access control and prevent header spoofing.
*   Monitor web server logs for suspicious POST requests to the /wp-json/litespeed/v1/notify_ccss and /wp-json/litespeed/v1/notify_ucss endpoints.

---
title: Royal Elementor Addons Plugin SSRF Vulnerability
slug: 2024-01-royal-elementor-ssrf
description: The Royal Elementor Addons plugin for WordPress is vulnerable to Server-Side Request Forgery (SSRF) allowing authenticated attackers with Contributor-level access or higher to make arbitrary requests and retrieve sensitive information from internal services.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - ssrf
  - cve-2026-6229
  - plugin
vendors:
  - WordPress
products:
  - Royal Elementor Addons <= 1.7.1057
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6229
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6229
rules:
  - title: Detect Royal Elementor Addons SSRF Attempt via URL Parameter
    description: Detects potential Server-Side Request Forgery (SSRF) attempts targeting the Royal Elementor Addons plugin by identifying requests containing 'docs.google.com/spreadsheets' in the URL parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Royal Elementor Addons SSRF Attempt via fopen Function
    description: Detects potential Server-Side Request Forgery (SSRF) attempts targeting the Royal Elementor Addons plugin by identifying requests to the fopen function with a suspicious domain in the URL parameter.
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

The Royal Elementor Addons plugin, a popular WordPress extension, contains a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-6229) in versions up to and including 1.7.1057. This flaw stems from inadequate validation of user-provided URLs within the `render_csv_data()` function. Attackers can bypass the validation by including 'docs.google.com/spreadsheets' in a query parameter. The vulnerability is triggered because the plugin uses these URLs in `fopen()` calls without implementing adequate safeguards to prevent access to internal or private network addresses. This vulnerability enables authenticated attackers with Contributor-level access or higher to craft malicious requests, potentially exposing sensitive internal data. Successful exploitation allows attackers to probe internal network resources, access configuration files, and potentially escalate attacks further.

## Attack Chain

1.  An attacker authenticates to the WordPress site with Contributor-level access or higher.
2.  The attacker crafts a malicious HTTP request targeting the vulnerable `render_csv_data()` function within the Royal Elementor Addons plugin.
3.  The malicious request includes a user-supplied URL containing 'docs.google.com/spreadsheets' within a query parameter to bypass initial validation checks.
4.  The plugin's `render_csv_data()` function receives the crafted URL without proper sanitization or validation against internal or private network addresses.
5.  The `fopen()` function is called with the attacker-controlled URL, initiating an outbound request from the WordPress server.
6.  If the URL points to an internal resource, the WordPress server retrieves the resource content.
7.  The attacker receives the content of the internal resource in the response from the WordPress server.
8.  The attacker analyzes the retrieved content for sensitive information, such as configuration files, API keys, or internal service details.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-6229) can lead to the exposure of sensitive internal information, potentially impacting all organizations using the Royal Elementor Addons plugin for WordPress version 1.7.1057 and below. This may include internal configuration files, API keys, database credentials, or other sensitive data accessible through internal services. The severity is high due to the potential for attackers to pivot from this vulnerability and further compromise the WordPress server or the internal network.

## Recommendation

*   Upgrade the Royal Elementor Addons plugin to a version higher than 1.7.1057 to patch CVE-2026-6229.
*   Deploy the Sigma rule "Detect Royal Elementor Addons SSRF Attempt via URL Parameter" to identify malicious requests targeting the `render_csv_data()` function in your web server logs.
*   Implement strict network segmentation and firewall rules to limit access from the WordPress server to internal resources, mitigating the impact of potential SSRF vulnerabilities.

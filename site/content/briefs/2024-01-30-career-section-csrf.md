---
title: Career Section WordPress Plugin CSRF Vulnerability Leading to Arbitrary File Deletion
slug: 2024-01-30-career-section-csrf
description: The Career Section WordPress plugin, versions 1.6 and earlier, is vulnerable to cross-site request forgery (CSRF), allowing unauthenticated attackers to delete arbitrary files on the server by tricking a site administrator.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - csrf
  - file-deletion
  - cve-2025-14868
products:
  - Career Section Plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2025-14868
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-14868
rules:
  - title: Detect Career Section Plugin Arbitrary File Deletion Attempt
    description: Detects potential attempts to exploit the Career Section WordPress plugin's arbitrary file deletion vulnerability via CSRF.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect Missing or Invalid Nonce in Career Section Plugin Request
    description: Detects requests to the Career Section plugin's 'appform_options_page' without a valid nonce, potentially indicating a CSRF attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Career Section plugin for WordPress, a tool designed for managing career-related content, is susceptible to a critical security vulnerability: Cross-Site Request Forgery (CSRF). This flaw affects all versions of the plugin up to and including version 1.6. The vulnerability stems from the insufficient validation of nonces and file paths within the 'appform_options_page_html' function when handling delete actions. An unauthenticated attacker can exploit this weakness to craft a malicious request that, if triggered by a logged-in administrator, leads to the deletion of arbitrary files on the server. This is particularly concerning as it grants attackers a pathway to potentially disrupt website functionality, compromise sensitive data, or even gain complete control over the affected WordPress installation. The vulnerability was reported under CVE-2025-14868.

## Attack Chain

1. An attacker identifies a WordPress site using a vulnerable version of the Career Section plugin (<= 1.6).
2. The attacker crafts a malicious HTTP request targeting the 'appform_options_page_html' function. This request is designed to trigger the file deletion functionality.
3. The crafted request omits or provides an invalid nonce value, exploiting the lack of proper nonce validation.
4. The attacker embeds this malicious request within a link or an image tag hosted on a website or sent via email.
5. The attacker social engineers a logged-in WordPress administrator to click the malicious link (e.g., via phishing or a compromised website).
6. The administrator's browser unknowingly sends the forged request to the WordPress server.
7. Due to the missing nonce validation and insufficient file path validation, the server processes the request and deletes the file specified in the request.
8. The attacker achieves arbitrary file deletion on the WordPress server, potentially leading to website defacement, data loss, or further compromise.

## Impact

Successful exploitation of this CSRF vulnerability (CVE-2025-14868) allows unauthenticated attackers to delete arbitrary files on the affected WordPress server. This can lead to significant data loss, website defacement, or even a complete compromise of the WordPress installation. While the exact number of affected websites is unknown, the widespread use of WordPress and the Career Section plugin suggests a potentially broad impact. Organizations using this plugin are at risk of having their websites disrupted or sensitive data exposed.

## Recommendation

*   Immediately update the Career Section plugin to a version greater than 1.6 to patch CVE-2025-14868.
*   Implement a web application firewall (WAF) rule to detect and block suspicious requests to the 'appform_options_page_html' function that lack proper nonce values.
*   Deploy the Sigma rule `Detect Career Section Plugin Arbitrary File Deletion Attempt` to your SIEM to monitor for exploitation attempts.
*   Educate WordPress administrators about the risks of CSRF attacks and the importance of verifying the legitimacy of links before clicking them.

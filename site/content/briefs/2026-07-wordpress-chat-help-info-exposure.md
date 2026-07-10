---
title: 'CVE-2026-15291: WordPress Chat Help Plugin Sensitive Information Exposure'
slug: 2026-07-wordpress-chat-help-info-exposure
description: Unauthenticated attackers can exploit CVE-2026-15291, a vulnerability in the Chat Help - Click to Chat Button & Form WordPress plugin (versions up to and including 3.1.3), due to a lack of authentication and authorization checks on specific REST API endpoints (/wp-json/chat-help/v1/leads and /wp-json/chat-help/v1/leads/{id}), allowing them to extract sensitive user data, including names, email addresses, phone numbers, WhatsApp messages, complete geolocation data, device fingerprinting, and WordPress account credentials for logged-in users who submitted forms.
date: "2026-07-10T05:21:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - information-disclosure
  - rest-api
  - cve
vendors:
  - Chat Help
products:
  - Chat Help – Click to Chat Button & Form plugin for WordPress (< 3.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Chat Help – Click to Chat Button & Form plugin for WordPress is vulnerable to Sensitive Information Exposure... via the REST API endpoints /wp-json/chat-help/v1/leads and /wp-json/chat-help/v1/leads/{id}.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This makes it possible for unauthenticated attackers to extract sensitive data including customer names, email addresses, phone numbers, WhatsApp messages, complete geolocation data... and WordPress account credentials... who submit forms.
    confidence_band: high
cves:
  - id: CVE-2026-15291
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15291
rules:
  - title: Detects CVE-2026-15291 Exploitation - WordPress Chat Help Plugin Info Exposure
    description: Detects exploitation attempts against CVE-2026-15291, where unauthenticated attackers access sensitive data via vulnerable REST API endpoints in the Chat Help - Click to Chat Button & Form WordPress plugin.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1005
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Unauthenticated attackers can exploit CVE-2026-15291, a critical sensitive information exposure vulnerability in the "Chat Help - Click to Chat Button & Form" plugin for WordPress. All versions up to and including 3.1.3 are affected. The flaw stems from the plugin's REST API endpoints, specifically `/wp-json/chat-help/v1/leads` and `/wp-json/chat-help/v1/leads/{id}`, which lack essential authentication and authorization checks. This oversight allows anyone to directly query these endpoints and retrieve a wealth of sensitive data. This includes customer names, email addresses, phone numbers, WhatsApp messages, comprehensive geolocation data (IP addresses, city, country, ISP, coordinates), device fingerprinting information (browser, OS, screen resolution), and even WordPress account credentials (user IDs, usernames, emails, names) belonging to logged-in users who have interacted with the forms. This vulnerability poses a significant risk to user privacy and could facilitate further targeted attacks.

## Attack Chain

1. An attacker identifies a target WordPress website utilizing the vulnerable "Chat Help - Click to Chat Button & Form" plugin (versions 3.1.3 or earlier).
2. The attacker, unauthenticated, crafts an HTTP GET request to the publicly exposed REST API endpoint `/wp-json/chat-help/v1/leads`.
3. Due to the absence of authentication and authorization mechanisms, the vulnerable plugin processes the request without validating the attacker's identity or permissions.
4. The plugin queries its internal database for all stored "lead" records, which contain sensitive user interactions and data.
5. The plugin generates a JSON response containing comprehensive data for all leads, including customer names, email addresses, phone numbers, and WhatsApp messages.
6. The attacker receives this JSON response, gaining access to a wide array of personal identifiable information.
7. The response also includes detailed geolocation data such as IP addresses, city, country, ISP, and geographic coordinates for each lead.
8. Furthermore, the attacker can extract device fingerprinting information (browser, OS, screen resolution) and WordPress account credentials (user IDs, usernames, emails) associated with users who submitted forms.

## Impact

Successful exploitation of CVE-2026-15291 leads to a severe breach of personal and sensitive information for all individuals who have interacted with the Chat Help plugin's forms. This directly compromises user privacy and trust. The exposed data, including email addresses, phone numbers, geolocation, and even WordPress account details, can be leveraged for highly targeted phishing campaigns, spam, identity theft, or credential stuffing attacks against other services. While no specific victim count is available, any organization using the affected plugin on their WordPress site is at risk of exposing their customer and visitor data. Businesses handling customer inquiries, support, or marketing via these forms are particularly vulnerable.

## Recommendation

* Immediately update the "Chat Help - Click to Chat Button & Form" plugin to a patched version (3.1.4 or higher) to remediate [CVE-2026-15291](https://nvd.nist.gov/vuln/detail/CVE-2026-15291).
* Deploy the provided Sigma rule to your SIEM to detect suspicious access attempts to the exposed REST API endpoints.
* Monitor web server logs for your WordPress instance for unusual or excessive GET requests to `/wp-json/chat-help/v1/leads` or `/wp-json/chat-help/v1/leads/{id}`.
* Implement strong authentication and authorization best practices for all public-facing APIs on your web applications.

---
title: Grav API Plugin Vulnerable to CORS Misconfiguration Allowing Data Exposure and Unauthorized Operations
slug: 2026-07-grav-api-cors-misconfiguration
description: 'The Grav API plugin before version 1.0.0-rc.16 contains a CORS misconfiguration that sets `Access-Control-Allow-Origin: *` by default, enabling an attacker to perform authenticated cross-origin requests from a malicious website after obtaining a valid API token, leading to sensitive data exfiltration and unauthorized write operations.'
date: "2026-07-17T02:42:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - cors
  - misconfiguration
  - data-exfiltration
  - rce-potential
vendors:
  - Grav
products:
  - Grav API plugin (< 1.0.0-rc.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'The Grav API plugin (getgrav/grav-plugin-api) before 1.0.0-rc.16 shipped Access-Control-Allow-Origin: * as its default CORS configuration on all responses, including authenticated endpoints'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1559
    technique_name: Interprocess Communication
    evidence: Because the plugin accepts credentials via the Authorization and X-API-Token headers ..., an attacker ... can issue fully authenticated cross-origin requests from any malicious website to read sensitive data and perform write operations
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Local System
    evidence: an attacker ... can issue fully authenticated cross-origin requests from any malicious website to read sensitive data
    confidence_band: high
cves:
  - id: CVE-2026-62387
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62387
rules:
  - title: Detects CVE-2026-62387 exploitation - Suspicious Cross-Origin Request to Grav API
    description: Detects web requests to Grav API endpoints with an 'Origin' header from an unexpected domain, indicating potential exploitation of the CORS misconfiguration CVE-2026-62387. This rule requires tuning with known legitimate Grav domains.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
      - initial_access
    techniques:
      - T1190
      - T1530
      - T1559
    data_sources:
      - webserver
rules_count: 1
---

A critical Cross-Origin Resource Sharing (CORS) misconfiguration has been identified in the Grav API plugin (getgrav/grav-plugin-api) versions prior to 1.0.0-rc.16. This vulnerability, tracked as CVE-2026-62387, stems from the plugin's default configuration of `Access-Control-Allow-Origin: *` on all responses, including authenticated API endpoints and preflight `OPTIONS` requests. This lax CORS policy allows any website to make authenticated requests to the Grav API once an attacker has acquired a valid API token. Attackers can leverage various methods such as log leakage, browser history analysis, or network capture to obtain these tokens. The impact for defenders is significant as this flaw bypasses browser same-origin policy, enabling attackers to read sensitive data and execute write operations programmatically from their malicious domains, effectively taking over user accounts within the Grav system.

## Attack Chain

1. Attacker compromises a valid Grav API access token for a user account through various means, such as log leakage, sniffing network traffic, or exploiting browser vulnerabilities that expose session data.
2. Attacker crafts a malicious website containing JavaScript code designed to interact with the vulnerable Grav API endpoints.
3. A user, whose API token has been compromised, browses to the attacker's malicious website.
4. The malicious JavaScript on the attacker's site initiates a cross-origin HTTP request (e.g., `GET`, `POST`, `OPTIONS`) to the Grav API, including the stolen access token in the `Authorization` or `X-API-Token` header.
5. Due to the `Access-Control-Allow-Origin: *` header sent by the Grav API plugin, the user's browser allows the malicious JavaScript to process the response from the Grav API, bypassing the same-origin policy.
6. The attacker's JavaScript reads sensitive data (e.g., user profiles, content) from the Grav system or performs unauthorized write operations (e.g., modifying content, user settings) using the compromised token.
7. The collected sensitive data is then exfiltrated from the user's browser to an attacker-controlled server.

## Impact

Successful exploitation of CVE-2026-62387 can lead to unauthorized access to sensitive data and critical system functions within Grav instances. Attackers can read any data accessible to the compromised user's API token, potentially exposing private content, user information, or system configurations. Furthermore, the ability to perform write operations means attackers can deface websites, inject malicious content, alter user accounts, or even disrupt Grav site functionality. The specific damage and number of victims would depend on the privileges associated with the compromised API token and the attacker's objectives.

## Recommendation

* Immediately patch the Grav API plugin to version 1.0.0-rc.16 or later to address CVE-2026-62387.
* Review web server access logs for the patterns identified in the "Detects CVE-2026-62387 exploitation - Suspicious Cross-Origin Request to Grav API" Sigma rule, specifically looking for Grav API requests with `Origin` headers from unexpected domains.
* Configure web application firewalls (WAFs) to block requests to Grav API endpoints that have an `Origin` header not matching your legitimate Grav domain(s) or a predefined allowlist of trusted origins.
* Implement strict logging and monitoring for all Grav API access, focusing on authentication attempts, data retrieval, and modification actions.

---
title: PrestaShop Stored XSS Vulnerability via Unprotected Template Variables
slug: 2024-01-03-prestashop-xss
description: Multiple stored XSS vulnerabilities exist in PrestaShop, where an attacker with database access can exploit unprotected variables in back-office templates to execute malicious scripts in a user's browser.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prestashop
  - xss
  - vulnerability
  - web-application
vendors:
  - PrestaShop
products:
  - PrestaShop
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-35pf-37c6-jxjv
rules:
  - title: Detect Potential XSS Attempts in PrestaShop Backoffice via URI
    description: Detects potential XSS attempts in PrestaShop backoffice based on suspicious URI patterns
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious HTTP Referer to PrestaShop Admin Panel
    description: Detects access to PrestaShop admin panel from an external domain, which may indicate an attempt to exploit vulnerabilities from a malicious origin.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Modification of PrestaShop Configuration Files
    description: Detects modification of PrestaShop configuration files, which may indicate unauthorized access or an attempt to inject malicious code.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Multiple stored Cross-Site Scripting (XSS) vulnerabilities have been identified in PrestaShop versions prior to 8.2.5 and in versions 9.0.0-alpha.1 to 9.1.0. These vulnerabilities allow an attacker who has the ability to inject data into the database, either through limited back-office access or by exploiting a pre-existing vulnerability, to execute arbitrary JavaScript code in the context of a back-office user's browser. This is achieved by exploiting unprotected variables in back-office templates. Successful exploitation could lead to account takeover, data theft, or further compromise of the PrestaShop installation. The vulnerability is identified as CVE-2026-33673. Patches are available in versions 8.2.5 and 9.1.0.

## Attack Chain

1. **Initial Compromise:** The attacker gains unauthorized access to the PrestaShop back office, either through brute-force attacks, credential stuffing, or exploitation of other vulnerabilities (e.g., SQL injection, authentication bypass).
2. **Database Injection:** The attacker injects malicious JavaScript code into a database field that is later rendered in a back-office template. This can be achieved by manipulating input fields or directly modifying database records if sufficient privileges are obtained.
3. **Template Rendering:** A back-office user accesses a page that renders the template containing the injected malicious code.
4. **XSS Execution:** The injected JavaScript code executes within the user's browser session due to the lack of proper output escaping or sanitization in the template.
5. **Session Hijacking/Account Takeover:** The attacker's JavaScript code steals the user's session cookies or other authentication tokens.
6. **Privilege Escalation:** Using the stolen session, the attacker gains access to the back-office user's account, potentially with administrative privileges.
7. **Further Exploitation:** The attacker uses the compromised account to modify store settings, install malicious modules, steal sensitive data (customer information, financial data), or deface the website.
8. **Persistence:** The attacker establishes persistent access by creating rogue administrator accounts or installing backdoors within the PrestaShop system.

## Impact

Successful exploitation of these XSS vulnerabilities can have severe consequences for PrestaShop store owners and their customers. An attacker can gain full control of the store's back office, leading to unauthorized access to sensitive data, including customer information and financial details. This can result in financial losses, reputational damage, and legal liabilities for the store owner. While specific victim counts are unavailable, the widespread use of PrestaShop makes this a potentially high-impact vulnerability.

## Recommendation

*   Upgrade PrestaShop installations to version 8.2.5 or 9.1.0 to patch CVE-2026-33673.
*   Implement strict input validation and output encoding on all user-supplied data to prevent XSS attacks.
*   Monitor web server logs for suspicious activity, such as unusual requests to back-office pages or attempts to inject malicious code into database fields (see example Sigma rule).
*   Enforce strong password policies and multi-factor authentication for all back-office user accounts.
*   Regularly audit PrestaShop installations for security vulnerabilities and apply security patches promptly.

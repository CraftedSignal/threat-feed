---
title: Gravity Forms Plugin Stored XSS Vulnerability (CVE-2026-5113)
slug: 2026-05-gravityforms-xss
description: The Gravity Forms plugin for WordPress is vulnerable to stored cross-site scripting (XSS) via Consent field hidden inputs, allowing unauthenticated attackers to inject arbitrary web scripts that execute when an administrator views the entries list page.
date: "2026-05-02T06:16:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - wordpress
  - gravityforms
  - cve-2026-5113
  - stored-xss
vendors:
  - WordPress
products:
  - Gravity Forms plugin <= 2.10.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5113
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5113
rules:
  - title: Detect Suspicious Gravity Forms Consent Field Submission
    description: Detects potentially malicious submissions to Gravity Forms consent fields containing script tags.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Admin Page Access after Gravity Forms XSS
    description: Detects access to WordPress admin pages after a Gravity Forms XSS has been potentially triggered, indicating exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Gravity Forms plugin for WordPress, a popular form builder, contains a stored cross-site scripting (XSS) vulnerability identified as CVE-2026-5113. This flaw affects versions up to and including 2.10.0. The vulnerability stems from a flawed state validation mechanism combined with insufficient output escaping within the Consent field's hidden inputs. An unauthenticated attacker can exploit this by injecting malicious JavaScript code into form entries. This malicious code is then executed when an authenticated administrator accesses the Entries List page within the WordPress administration panel, potentially leading to account compromise or other malicious actions performed within the administrator's session. Successful exploitation allows attackers to execute arbitrary web scripts in the context of an administrator's browser.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious payload containing XSS code within a Gravity Forms Consent field. The payload leverages HTML tags like `<svg>` that `wp_kses()` will strip.
2.  The attacker submits the crafted form entry to the WordPress site.
3.  The Gravity Forms plugin's state validation mechanism calculates two hashes: one for the raw input and another after sanitization via `wp_kses()`.
4.  Due to the nature of the XSS payload, the `wp_kses()` function strips the `<svg>` tag, resulting in a matching hash for the sanitized input.
5.  The flawed validation logic fails to detect the malicious intent because at least one hash matches the original state, allowing the malicious raw value (containing the XSS payload) to be stored in the database.
6.  An authenticated administrator logs into the WordPress administration panel.
7.  The administrator navigates to the Entries List page for the affected Gravity Form.
8.  The stored malicious consent label is retrieved from the database and output without proper escaping, causing the XSS payload to execute within the administrator's browser session.

## Impact

Successful exploitation of CVE-2026-5113 allows unauthenticated attackers to execute arbitrary web scripts within the context of an authenticated administrator's browser session. This can lead to a variety of malicious outcomes, including account compromise, data theft, modification of website content, or further propagation of the attack to other administrative users. The severity of the impact depends on the privileges held by the compromised administrator account.

## Recommendation

*   Upgrade the Gravity Forms plugin to the latest version, which includes a fix for CVE-2026-5113.
*   Implement a Web Application Firewall (WAF) rule to filter out requests containing potentially malicious XSS payloads targeting the Gravity Forms Consent field.
*   Monitor web server logs for suspicious activity related to form submissions containing encoded or obfuscated JavaScript code. Analyze HTTP request parameters for unusual characters or patterns indicative of XSS attempts.
*   Enable output escaping on form entries to prevent stored XSS attacks.

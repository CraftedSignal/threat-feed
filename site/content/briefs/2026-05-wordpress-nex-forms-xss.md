---
title: NEX-Forms WordPress Plugin Vulnerable to Stored Cross-Site Scripting (CVE-2026-5063)
slug: 2026-05-wordpress-nex-forms-xss
description: The NEX-Forms WordPress plugin is vulnerable to stored XSS via POST parameter key names, allowing unauthenticated attackers to inject arbitrary web scripts.
date: "2026-05-03T06:15:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - stored-xss
  - cve-2026-5063
vendors:
  - WordPress
products:
  - NEX-Forms – Ultimate Forms Plugin for WordPress plugin <= 9.1.11
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5063
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5063
  - https://plugins.trac.wordpress.org/changeset/3513524/nex-forms-express-wp-form-builder
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/9bac82ee-55bf-4381-b441-115a675e4834?source=cve
rules:
  - title: Detect Suspicious NEX-Forms POST Requests
    description: Detects suspicious POST requests to WordPress pages using the NEX-Forms plugin with potentially malicious JavaScript code in parameter names, indicative of CVE-2026-5063 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Stored XSS in WordPress POST Requests via Keywords
    description: Detects stored XSS attempts via common keywords in WordPress POST requests.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The NEX-Forms – Ultimate Forms Plugin for WordPress, versions up to and including 9.1.11, is susceptible to a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-5063). This flaw stems from inadequate input sanitization and output escaping within the `submit_nex_form()` function. Unauthenticated attackers can exploit this vulnerability by injecting malicious JavaScript code through POST parameter key names. Successful exploitation allows the attacker to execute arbitrary scripts in the context of a user's browser when they access a page containing the injected script, potentially leading to session hijacking, defacement, or redirection to malicious sites. The vulnerability was reported to Wordfence and a patch has been released.

## Attack Chain

1.  The attacker crafts a malicious HTTP POST request to a WordPress page that utilizes the vulnerable NEX-Forms plugin.
2.  The POST request includes specially crafted parameter key names designed to inject JavaScript code.
3.  The `submit_nex_form()` function processes the POST request without properly sanitizing or escaping the malicious input.
4.  The injected JavaScript code is stored in the WordPress database.
5.  A legitimate user accesses a page where the form data, including the malicious script, is displayed.
6.  The stored JavaScript code executes within the user's browser in the context of the WordPress page.
7.  The attacker can then perform actions such as stealing cookies, redirecting the user, or modifying the page content.

## Impact

Successful exploitation of this stored XSS vulnerability allows an unauthenticated attacker to inject arbitrary JavaScript code into pages using the NEX-Forms plugin. This can lead to various malicious outcomes, including user session hijacking, website defacement, or redirection to phishing sites. As the vulnerability is stored, every user who visits a page containing the malicious script will be affected until the vulnerability is patched and the malicious input is removed. The severity is rated as HIGH with a CVSS base score of 7.2.

## Recommendation

*   Upgrade the NEX-Forms – Ultimate Forms Plugin for WordPress to a version beyond 9.1.11 to patch CVE-2026-5063.
*   Deploy the Sigma rule `Detect Suspicious NEX-Forms POST Requests` to identify potential exploitation attempts.
*   Monitor web server logs for suspicious POST requests containing potentially malicious JavaScript code in parameter names.

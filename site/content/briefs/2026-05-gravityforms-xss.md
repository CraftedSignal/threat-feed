---
title: Gravity Forms Plugin Stored XSS Vulnerability (CVE-2026-5109)
slug: 2026-05-gravityforms-xss
description: A stored cross-site scripting (XSS) vulnerability exists in the Gravity Forms plugin for WordPress versions up to 2.10.0, allowing unauthenticated attackers to inject arbitrary web scripts into entry data that executes when administrators view entry details.
date: "2026-05-02T06:16:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - stored-xss
  - cve-2026-5109
  - gravity-forms
vendors:
  - WordPress
products:
  - Gravity Forms plugin <= 2.10.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5109
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5109
rules:
  - title: Detect Gravity Forms XSS via Product Option
    description: Detects potential exploitation attempts targeting the Gravity Forms Product Option field to inject malicious JavaScript.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
  - title: Detect Gravity Forms Order Summary XSS
    description: Detects access to the Gravity Forms order summary page, potentially indicating exploitation of stored XSS.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5109 is a stored XSS vulnerability affecting the Gravity Forms plugin for WordPress, specifically versions up to and including 2.10.0. This flaw arises from inadequate validation and output escaping of Product Option field values. An unauthenticated attacker can exploit this by injecting malicious JavaScript code into the product option fields of a form submission. The vulnerability is triggered when an administrator views the entry details through the Order Summary section within the WordPress administration panel. This occurs because the application stores the raw, unsanitized value in the database and then directly outputs the `option_label` without proper escaping, leading to the execution of the injected script within the administrator's browser. This can lead to session hijacking, defacement, or other malicious activities within the context of the administrator's WordPress session.

## Attack Chain

1.  The attacker accesses a WordPress site running the vulnerable Gravity Forms plugin (<= 2.10.0).
2.  The attacker identifies a Gravity Form with a Product Option field.
3.  The attacker crafts a malicious payload containing JavaScript code and injects it into the Product Option field during form submission. This payload is designed to execute arbitrary code within an administrator's session.
4.  The form is submitted with the malicious payload. The vulnerable validation logic accepts the malicious value because the `wp_kses()` sanitized version matches a legitimate option.
5.  The raw, unsanitized value, including the malicious JavaScript, is stored in the WordPress database.
6.  An administrator logs into the WordPress administration panel and navigates to the Gravity Forms entries.
7.  The administrator views the details of the entry containing the malicious payload through the Order Summary section. Specifically, `view-order-summary.php` at line 32.
8.  The `option_label` containing the injected JavaScript is output without proper escaping, causing the JavaScript code to execute within the administrator's browser session. This constitutes the stored XSS vulnerability, enabling the attacker to perform actions with the administrator's privileges.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary JavaScript code in the context of an administrator's browser session. This can lead to privilege escalation, session hijacking, defacement of the WordPress site, or the injection of malicious content into the website. Due to the wide usage of WordPress and the Gravity Forms plugin, a successful attack can have a broad impact, potentially affecting thousands of websites and their administrators. The CVSS v3.1 base score is 7.2, indicating a high severity vulnerability.

## Recommendation

*   Upgrade the Gravity Forms plugin to a version greater than 2.10.0 to patch the vulnerability (CVE-2026-5109).
*   Deploy the Sigma rule "Detect Gravity Forms XSS via Product Option" to detect potential exploitation attempts targeting Product Option fields.
*   Implement input validation and output escaping on all user-supplied data within WordPress plugins to prevent XSS vulnerabilities.
*   Enable web server logging and monitor for suspicious activity originating from WordPress admin interfaces.

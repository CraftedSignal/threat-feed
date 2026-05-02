---
title: Gravity Forms Plugin Stored XSS Vulnerability (CVE-2026-5111)
slug: 2026-05-gravityforms-xss
description: A stored cross-site scripting (XSS) vulnerability, designated as CVE-2026-5111, affects the Gravity Forms plugin for WordPress versions up to and including 2.10.0, allowing unauthenticated attackers to inject arbitrary web scripts executed when an administrator views entry details.
date: "2026-05-02T06:16:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - stored xss
  - wordpress
  - gravity forms
vendors:
  - WordPress
products:
  - Gravity Forms plugin <= 2.10.0
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5111
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5111
rules:
  - title: Detect Gravity Forms XSS via Form Submission
    description: Detects potential XSS attacks against Gravity Forms by looking for script tags or event handlers within POST requests.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
  - title: Detect Gravity Forms XSS via Repeater Field
    description: Detects potential XSS attacks against Gravity Forms involving repeater fields by looking for script tags or event handlers within POST requests targeting repeater functionality.
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

The Gravity Forms plugin for WordPress is susceptible to a stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-5111, in versions up to and including 2.10.0. The flaw lies in the insufficient input validation and output escaping mechanisms for Hidden Product field values specifically when they are utilized within Repeater fields. This occurs because repeater subfields bypass standard state validation procedures, and the Hidden Product validate() method focuses solely on the quantity field. Consequently, the product name field, which is later rendered without proper escaping in the get_value_entry_detail() method, becomes a point of injection. Successful exploitation enables unauthenticated attackers to inject arbitrary web scripts by submitting malicious form data. These scripts are then executed whenever an administrator accesses and views the details of the compromised entry within the WordPress admin panel.

## Attack Chain

1. An unauthenticated attacker crafts a malicious form submission containing a Hidden Product field within a Repeater field.
2. The malicious payload is injected into the product name field of the Hidden Product field.
3. Due to bypassed state validation checks within Repeater fields, the injected payload bypasses the standard input validation.
4. The Hidden Product field's `validate()` method only validates the quantity field, ignoring the malicious product name.
5. The form submission is processed, and the malicious data is stored in the WordPress database.
6. When an administrator views the form entry details, the `get_value_entry_detail()` method retrieves the stored malicious data.
7. The `get_value_entry_detail()` method outputs the product name field without proper escaping.
8. The injected JavaScript code is executed in the administrator's browser within the context of the WordPress admin session, potentially leading to account compromise or site defacement.

## Impact

Successful exploitation of this stored XSS vulnerability (CVE-2026-5111) allows unauthenticated attackers to execute arbitrary JavaScript code within the administrator's browser session when viewing the affected Gravity Forms entry. This can lead to a range of malicious activities, including stealing administrator cookies, defacing the WordPress site, or creating new administrative accounts. The severity is amplified by the unauthenticated nature of the attack, allowing anyone to submit malicious forms.

## Recommendation

*   Upgrade the Gravity Forms plugin to a version greater than 2.10.0 to patch CVE-2026-5111 (see Affected Products).
*   Deploy the Sigma rule "Detect Gravity Forms XSS via Form Submission" to detect potential exploitation attempts by monitoring for suspicious script injections in HTTP POST requests to the WordPress installation (see Rules).
*   Implement additional input validation and output escaping mechanisms for all form fields, especially those within Repeater fields, to prevent similar XSS vulnerabilities in the future.

---
title: Gravity Forms Plugin Unauthenticated Stored XSS Vulnerability
slug: 2024-01-gravity-forms-xss
description: The Gravity Forms plugin for WordPress is vulnerable to unauthenticated stored cross-site scripting (XSS) in versions up to 2.10.0, allowing attackers to inject arbitrary JavaScript code into the product name field within repeater fields, which executes when an administrator views the affected entry.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - wordpress
  - gravityforms
vendors:
  - WordPress
products:
  - Gravity Forms plugin <= 2.10.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5110
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5110
rules:
  - title: Detect Gravity Forms XSS Attempt
    description: Detects attempts to inject XSS payloads into the Gravity Forms SingleProduct field within Repeater fields.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Gravity Forms Admin Entry Access with Potential XSS
    description: Detects access to Gravity Forms admin entry pages which may contain stored XSS payloads.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Gravity Forms plugin, a widely used WordPress plugin, is susceptible to an unauthenticated stored cross-site scripting (XSS) vulnerability. This flaw, identified as CVE-2026-5110, affects versions up to and including 2.10.0. The vulnerability stems from inadequate input validation and output escaping specifically within the SingleProduct field when it is nested inside a Repeater field. This bypasses normal state validation, allowing attackers to inject malicious HTML and JavaScript into the product name field. The injected payload is then stored unsanitized in the database. This vulnerability allows unauthenticated attackers to inject arbitrary web scripts that execute whenever an administrator accesses an entry containing the malicious payload through the WordPress admin interface.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious request to a WordPress endpoint utilizing the Gravity Forms plugin.
2.  The attacker injects arbitrary HTML and JavaScript into the 'product name' field (input .1) of a SingleProduct field nested within a Repeater field.
3.  Due to insufficient validation within the `validate_subfield()` method, the malicious input bypasses the state validation mechanism `(failed_state_validation())`.
4.  The `sanitize_entry_value()` method returns the raw, unsanitized value because HTML is not expected for the affected field type.
5.  The malicious input is stored in the WordPress database without proper sanitization or escaping.
6.  An administrator accesses the Gravity Forms entries page in the WordPress admin interface (wp-admin/admin.php?page=gf_entries).
7.  The `get_value_entry_detail()` method retrieves the malicious product name from the database and outputs it without proper escaping.
8.  The stored XSS payload executes in the administrator's browser, potentially allowing the attacker to perform actions with the administrator's privileges.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary JavaScript code in the context of an administrator's browser session. This can lead to account compromise, data theft, or further malicious activities within the WordPress administration panel. The vulnerability affects all users of the Gravity Forms plugin on WordPress installations with versions up to and including 2.10.0.

## Recommendation

*   Upgrade the Gravity Forms plugin to the latest version (greater than 2.10.0) to patch CVE-2026-5110.
*   Deploy the provided Sigma rule `Detect Gravity Forms XSS Attempt` to identify potential exploitation attempts by monitoring for specific patterns in HTTP requests.
*   Enable web server logging to capture detailed information about HTTP requests and responses, enabling the Sigma rule's effectiveness.

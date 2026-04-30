---
title: Everest Forms WordPress Plugin PHP Object Injection Vulnerability
slug: 2026-04-everest-forms-rce
description: The Everest Forms plugin for WordPress is vulnerable to PHP Object Injection (CVE-2026-3296) in versions up to 3.4.3, allowing unauthenticated attackers to execute arbitrary code by injecting serialized PHP objects via form fields.
date: "2026-04-08T02:16:04Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - wordpress
  - php
  - object-injection
  - rce
  - cve-2026-3296
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-3296
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3296
rules:
  - title: Detect Suspicious unserialize Call in Everest Forms
    description: Detects calls to the unserialize function in the Everest Forms plugin without specifying allowed classes, indicating a potential PHP Object Injection vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Form Submission with Serialized Data
    description: Detects POST requests to WordPress form submission endpoints containing serialized PHP objects.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Everest Forms plugin for WordPress, a widely used form builder, contains a critical PHP Object Injection vulnerability (CVE-2026-3296) affecting versions up to and including 3.4.3. This vulnerability stems from the insecure deserialization of user-supplied data within the `html-admin-page-entries-view.php` file. Specifically, the plugin uses PHP's `unserialize()` function on form entry metadata stored in the `wp_evf_entrymeta` table without specifying allowed classes, creating an exploitable condition. An unauthenticated attacker can inject malicious serialized PHP objects through any public form field. The `sanitize_text_field()` function fails to prevent these attacks because it doesn't strip serialization control characters. This allows attackers to execute arbitrary PHP code on the WordPress server when an administrator views form entries. This vulnerability poses a significant risk to WordPress sites using the Everest Forms plugin.

## Attack Chain

1. An unauthenticated attacker submits a malicious serialized PHP object through a public Everest Forms form field.
2. The submitted payload bypasses the `sanitize_text_field()` function due to the function's failure to remove serialization control characters.
3. The crafted serialized object is stored in the `wp_evf_entrymeta` database table associated with the form entry.
4. An administrator accesses the WordPress administration panel and navigates to the Everest Forms entries section.
5. The `html-admin-page-entries-view.php` file is executed to display form entries and their associated metadata.
6. The plugin retrieves the stored serialized object from the `wp_evf_entrymeta` table.
7. The `unserialize()` function is called on the retrieved data *without* the `allowed_classes` parameter, triggering PHP Object Injection.
8. The injected PHP object is instantiated, leading to arbitrary PHP code execution on the server, potentially granting the attacker complete control over the WordPress site.

## Impact

Successful exploitation of this vulnerability (CVE-2026-3296) can lead to complete compromise of the WordPress website. An attacker can gain remote code execution, allowing them to inject malware, deface the site, steal sensitive data (including user credentials and financial information), or use the compromised server as part of a botnet. Given the widespread use of the Everest Forms plugin, a large number of WordPress sites are potentially vulnerable. The CVSS v3.1 base score of 9.8 reflects the critical severity of this vulnerability.

## Recommendation

*   Immediately update the Everest Forms plugin to the latest version (greater than 3.4.3) to patch CVE-2026-3296.
*   Deploy the Sigma rule `Detect Suspicious unserialize Call in Everest Forms` to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for suspicious POST requests to WordPress form submission endpoints containing serialized PHP objects, as detected by the `Detect Suspicious Form Submission with Serialized Data` Sigma rule.
*   Implement a Web Application Firewall (WAF) rule to block requests containing serialized PHP objects in form submission data.

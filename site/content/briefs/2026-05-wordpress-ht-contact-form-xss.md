---
title: HT Contact Form WordPress Plugin Vulnerable to Stored XSS (CVE-2026-7052)
slug: 2026-05-wordpress-ht-contact-form-xss
description: The HT Contact Form – Drag & Drop Form Builder for WordPress plugin for WordPress is vulnerable to Stored Cross-Site Scripting (CVE-2026-7052) via the 'file_upload' parameter in versions up to 2.8.2, allowing unauthenticated attackers to inject arbitrary web scripts.
date: "2026-05-28T08:18:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stored-xss
  - wordpress
  - plugin
  - CVE-2026-7052
vendors:
  - WordPress
products:
  - HT Contact Form – Drag & Drop Form Builder for WordPress plugin <= 2.8.2
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
cves:
  - id: CVE-2026-7052
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7052
rules:
  - title: Detect CVE-2026-7052 Exploitation — HT Contact Form Stored XSS
    description: Detects CVE-2026-7052 exploitation — attempts to inject malicious JavaScript code via the 'file_upload' parameter in HT Contact Form submissions.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1059.007
    data_sources:
      - webserver
  - title: Detect Suspicious Script Tags in HTTP Query Parameters
    description: Detects script tags within HTTP query parameters which could indicate potential XSS attacks.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

The HT Contact Form – Drag & Drop Form Builder for WordPress plugin, a popular tool for creating contact forms on WordPress websites, is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability. Identified as CVE-2026-7052, this flaw affects all versions up to and including 2.8.2. The vulnerability lies within the 'file_upload' parameter, where insufficient input sanitization and output escaping allow unauthenticated attackers to inject arbitrary web scripts. Successful exploitation requires the 'Store Submissions' setting to be enabled in the plugin, as this setting determines whether unsanitized field values are persisted to the database. These persisted values are then rendered without proper escaping in the admin entry viewer, leading to XSS when an administrator views the submission. This poses a significant risk to WordPress sites using the vulnerable plugin, as malicious scripts can compromise administrator accounts and potentially the entire website.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious HTTP POST request to a WordPress page containing a HT Contact Form.
2.  The attacker injects a JavaScript payload into the 'file_upload' parameter of the form.
3.  The vulnerable HT Contact Form plugin processes the form submission without proper sanitization or output encoding of the 'file_upload' parameter.
4.  If the 'Store Submissions' setting is enabled, the malicious payload is stored in the WordPress database.
5.  An administrator logs into the WordPress admin panel.
6.  The administrator navigates to the HT Contact Form submissions page, triggering the rendering of the stored, unsanitized 'file_upload' value.
7.  The injected JavaScript payload executes within the administrator's browser session.
8.  The attacker gains control of the administrator's session, potentially leading to further compromise of the WordPress website, such as plugin modification or arbitrary code execution.

## Impact

Successful exploitation of this Stored XSS vulnerability (CVE-2026-7052) can lead to a complete compromise of the affected WordPress website. An attacker can inject malicious JavaScript code that executes within the administrator's browser, allowing them to steal credentials, modify website content, install malicious plugins, or redirect users to phishing sites. Given the popularity of the HT Contact Form plugin, a large number of WordPress websites are potentially vulnerable. The impact is magnified when considering that administrators typically have extensive privileges, enabling attackers to perform privileged actions.

## Recommendation

*   Upgrade the HT Contact Form – Drag & Drop Form Builder for WordPress plugin to the latest version (greater than 2.8.2) to patch CVE-2026-7052.
*   Deploy the provided Sigma rule to detect attempts to inject malicious JavaScript code into the `file_upload` parameter within HTTP POST requests targeting WordPress pages with contact forms.
*   Enable input validation and output encoding on all user-supplied data, especially for form fields, to prevent XSS vulnerabilities.
*   If upgrading is not immediately possible, disable the 'Store Submissions' setting within the HT Contact Form plugin as a temporary mitigation, albeit with reduced functionality.

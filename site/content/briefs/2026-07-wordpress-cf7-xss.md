---
title: WordPress Database for CF7 Plugin Stored Cross-Site Scripting (CVE-2026-13425)
slug: 2026-07-wordpress-cf7-xss
description: The Database for CF7 plugin for WordPress is vulnerable to stored Cross-Site Scripting (XSS) via Array Form Field Values, allowing unauthenticated attackers to inject arbitrary web scripts by sending specially crafted array-structured input to the Contact Form 7 REST API endpoint /wp-json/contact-form-7/v1/contact-forms/{id}/feedback, which are insufficiently sanitized and executed when a user accesses an affected page.
date: "2026-07-29T09:20:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - wordpress
  - xss
  - cve-2026-13425
  - stored-xss
  - plugin-vulnerability
products:
  - Database for CF7 plugin < 1.2.7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-13425
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13425
rules:
  - title: Detects CVE-2026-13425 Exploitation Attempt - WordPress CF7 XSS
    description: Detects CVE-2026-13425 exploitation attempts - unauthenticated attackers sending HTTP POST requests to the /wp-json/contact-form-7/v1/contact-forms/{id}/feedback endpoint with array-structured input (e.g., 'your-name[]') containing common XSS payloads in the query string.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-13425, affects all versions up to and including 1.2.6 of the "Database for CF7" plugin for WordPress. This flaw stems from insufficient input sanitization and output escaping when handling array-structured input for ordinary text fields (e.g., `your-name[]`). Unauthenticated attackers can exploit this by sending specially crafted HTTP POST requests containing malicious web scripts to the public REST API endpoint `/wp-json/contact-form-7/v1/contact-forms/{id}/feedback`. The plugin then stores this unsanitized input directly into its `wp_cf7db` database table, bypassing WordPress's default `wp_insert_post` and `wp_kses` filtering mechanisms. When a user, such as an administrator, subsequently views a page displaying the stored form data, the injected script executes in their browser context, leading to potential data theft, session hijacking, or website defacement.

## Attack Chain

1. An unauthenticated attacker crafts an HTTP POST request containing malicious JavaScript within a form field.
2. The attacker targets the `/wp-json/contact-form-7/v1/contact-forms/{id}/feedback` REST API endpoint of a vulnerable WordPress site.
3. The malicious JavaScript is embedded within array-structured input parameters (e.g., `your-name[]=payload`).
4. Due to insufficient input sanitization in the Database for CF7 plugin, this crafted input bypasses standard WordPress filtering.
5. The plugin stores the unsanitized malicious payload directly into the `wp_cf7db` custom database table using `$wpdb INSERT` and `serialize()`.
6. A legitimate user (e.g., a site administrator) accesses a WordPress page that displays the submitted form data containing the stored payload.
7. The browser renders the page, and the unsanitized malicious JavaScript retrieved from the database executes in the victim's browser context.
8. The attacker achieves arbitrary web script execution, potentially leading to session hijacking, credential theft, or further client-side compromise.

## Impact

Successful exploitation of CVE-2026-13425 allows unauthenticated attackers to execute arbitrary web scripts in the context of a victim's browser. This can lead to a range of severe consequences, including session hijacking, disclosure of sensitive information, defacement of web pages, or redirecting users to malicious sites. If an administrator account is compromised, attackers could gain full control over the affected WordPress site. While specific victim counts are not available for this newly disclosed vulnerability, the widespread use of WordPress and its plugins suggests a broad potential impact for organizations utilizing the Database for CF7 plugin in versions up to 1.2.6.

## Recommendation

* Immediately update the Database for CF7 plugin for WordPress to version 1.2.7 or higher to patch CVE-2026-13425.
* Deploy the Sigma rule "Detects CVE-2026-13425 Exploitation Attempt - WordPress CF7 XSS" to your SIEM to identify attempts to inject malicious array-structured input via the `/wp-json/contact-form-7/v1/contact-forms/{id}/feedback` endpoint.
* Block the URL `/wp-json/contact-form-7/v1/contact-forms/{id}/feedback` at the web application firewall (WAF) or web server level if immediate patching is not possible, ensuring the URL includes the wildcard `{id}` for the contact form ID.
* Monitor web server access logs for requests containing the IOC `/wp-json/contact-form-7/v1/contact-forms/{id}/feedback` combined with `[]` in the query string and suspicious characters, as described in the Sigma rule.

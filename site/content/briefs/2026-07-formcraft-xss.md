---
title: FormCraft WordPress Plugin Stored XSS Vulnerability
slug: 2026-07-formcraft-xss
description: The FormCraft plugin for WordPress, specifically versions up to and including 3.9.14, is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-7232) that allows unauthenticated attackers to inject arbitrary web scripts into web pages via manipulated form parameters due to insufficient input sanitization and output escaping, leading to script execution in users' browsers when accessing affected pages.
date: "2026-07-23T06:18:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - xss
  - plugin
  - web-application
vendors:
  - FormCraft
products:
  - FormCraft plugin (<= 3.9.14)
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
    technique_name: ""
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-7232
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7232
rules:
  - title: Detect CVE-2026-7232 Exploitation - FormCraft Stored XSS Injection
    description: Detects CVE-2026-7232 exploitation attempts by identifying HTTP POST requests to WordPress AJAX or REST API endpoints that contain common XSS payloads within query parameters structured as FormCraft's composite matrix sub-field keys (e.g., fieldN_M).
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

A critical stored Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-7232, affects the FormCraft plugin for WordPress in all versions up to and including 3.9.14. This flaw enables unauthenticated attackers to inject malicious web scripts into form submissions, which are then stored and executed in users' browsers when they visit pages displaying the injected content. The vulnerability arises from inadequate input sanitization and output escaping. Attackers exploit two primary mechanisms: either by injecting payloads into composite matrix sub-field keys (such as `field2_0` or `field2_1`) which bypass server-side sanitization and are stored raw, or by submitting array-typed field values where initial `htmlentities()` encoding is later reversed by `html_entity_decode()` before storage. Additionally, client-side DOMPurify checks are bypassed as matrix values arrive as arrays, not strings, preventing effective sanitization before being injected into the Document Object Model (DOM).

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP POST request containing an XSS payload within a form parameter to a vulnerable FormCraft installation. This payload can target composite matrix sub-field keys (e.g., `field2_0=payload`) or array-typed field values.
2. **Vector 1 (Composite Matrix Keys):** The FormCraft plugin processes the incoming form data. Specific composite matrix sub-field keys are processed without passing through the intended server-side sanitization routines.
3. The unsanitized XSS payload from these sub-field keys is directly inserted into the WordPress database via `$wpdb->insert()`.
4. **Vector 2 (Array-Typed Values):** Alternatively, array-typed field values containing an XSS payload are initially encoded using `htmlentities()` during submission.
5. However, during later processing or preparation for storage/rendering, the `htmlentities()` encoding is reversed by `html_entity_decode()` at `formcraft-main.php:2608` and `:2122`, effectively restoring the malicious script.
6. The restored or unsanitized XSS payload is then stored in the database.
7. When a legitimate user accesses a WordPress page or post that displays the stored form submission data, the FormCraft plugin retrieves the malicious content. Client-side DOMPurify, designed for sanitization, is bypassed because the matrix values are rendered as arrays, not strings, preventing the sanitization logic from executing.
8. The malicious web script is then directly injected into the user's browser DOM and executes in their context, potentially leading to session hijacking, credential theft, or defacement.

## Impact

Successful exploitation of CVE-2026-7232 allows unauthenticated attackers to perform stored Cross-Site Scripting (XSS) attacks. This can lead to a range of client-side impacts, including but not limited to, session hijacking, defacement of web pages, redirection to malicious sites, and theft of sensitive user information such as cookies or login credentials. The widespread use of WordPress and the FormCraft plugin means a broad attack surface, with any user accessing an affected page becoming a potential victim of the injected scripts, regardless of their privileges.

## Recommendation

* Patch CVE-2026-7232 immediately by updating the FormCraft WordPress plugin to version 3.9.15 or later.
* Deploy the Sigma rule "Detect CVE-2026-7232 Exploitation - FormCraft Stored XSS Injection" to your SIEM to identify attempts at injecting malicious scripts through FormCraft forms.
* Monitor `webserver` logs for HTTP POST requests to WordPress AJAX or form submission endpoints that contain suspicious XSS payloads in query parameters matching the `fieldN_M` pattern described in the attack chain.

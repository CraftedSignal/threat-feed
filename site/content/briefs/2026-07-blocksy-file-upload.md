---
title: 'CVE-2026-15158: Blocksy Companion Plugin Arbitrary File Upload Leading to RCE'
slug: 2026-07-blocksy-file-upload
description: The Blocksy Companion plugin for WordPress, specifically the premium version (blocksy-companion-pro) with the WooCommerce Extra (Advanced Reviews) and Custom Fonts extensions active, is vulnerable to Arbitrary File Upload (CVE-2026-15158). This flaw, present in versions up to and including 2.1.46, arises from improper file type validation within the `save_attachments` function, allowing double-extension files like `shell.woff2.php` to bypass MIME checks, which unauthenticated attackers can exploit to upload executable files, leading to remote code execution.
date: "2026-07-09T10:21:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web
  - vulnerability
  - arbitrary-file-upload
  - wordpress
vendors:
  - Blocksy
  - WordPress
products:
  - Blocksy Companion plugin (<= 2.1.46)
  - blocksy-companion-pro
  - WooCommerce Extra (Advanced Reviews)
  - Custom Fonts
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1609
    technique_name: Arbitrary File Upload
    evidence: The Blocksy Companion plugin for WordPress is vulnerable to Arbitrary File Upload
    confidence_band: high
cves:
  - id: CVE-2026-15158
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15158
---

A critical arbitrary file upload vulnerability, identified as CVE-2026-15158, affects the Blocksy Companion plugin for WordPress, specifically its premium version (blocksy-companion-pro) in all versions up to and including 2.1.46. The flaw resides within the `save_attachments` function, which is part of the Custom Fonts extension. The vulnerability stems from an insecure file type validation mechanism: a `wp_check_filetype_and_ext` filter uses `strpos()` to approve filenames containing `.woff2` or `.ttf` as substrings, rather than strictly validating them as file extensions. This allows unauthenticated attackers to upload malicious files disguised with double extensions (e.g., `shell.woff2.php`), bypassing MIME type checks. Exploitation of this vulnerability grants attackers the ability to upload executable files, leading directly to remote code execution (RCE) on the affected WordPress site. This issue is only exploitable when both the WooCommerce Extra (Advanced Reviews) and Custom Fonts extensions are active in the premium plugin. The free `blocksy-companion` plugin is not affected.

## Attack Chain

1. **Reconnaissance and Target Identification**: An unauthenticated attacker identifies a WordPress site running the Blocksy Companion Pro plugin (versions <= 2.1.46) with both the WooCommerce Extra (Advanced Reviews) and Custom Fonts extensions enabled.
2. **Malicious Payload Crafting**: The attacker crafts a PHP webshell or other executable script, naming it with a double extension such as `evil.woff2.php` or `backdoor.ttf.php`, to masquerade it as a legitimate font file.
3. **Arbitrary File Upload**: The attacker sends an unauthenticated HTTP POST request to the WordPress site's `admin-ajax.php` endpoint, targeting the plugin's `save_attachments` function. The request includes the crafted malicious file within the `multipart/form-data` body.
4. **MIME Type Validation Bypass**: The Blocksy Companion plugin's `wp_check_filetype_and_ext` filter, used by the Custom Fonts extension, processes the uploaded filename. Due to the use of `strpos()` for `.woff2` or `.ttf` substring checks instead of proper extension validation, the malicious `evil.woff2.php` file bypasses the intended MIME type restrictions.
5. **Malicious File Placement**: The vulnerable `save_attachments` function proceeds to save the malicious `evil.woff2.php` file to a publicly accessible directory on the WordPress server.
6. **Remote Code Execution**: The attacker sends a subsequent HTTP GET request directly to the newly uploaded `evil.woff2.php` file. The web server executes the PHP script, allowing the attacker to run arbitrary commands on the server with the permissions of the web server process, achieving remote code execution.

## Impact

Successful exploitation of CVE-2026-15158 allows unauthenticated attackers to achieve full remote code execution on affected WordPress installations. This can lead to complete compromise of the website and underlying server, including data theft, defacement, installation of backdoors, further network penetration, or integration into botnets. While no specific victim count is available, any WordPress site utilizing the premium Blocksy Companion Pro plugin with both WooCommerce Extra and Custom Fonts extensions active in versions up to 2.1.46 is at critical risk. The impact extends beyond the website itself, potentially affecting customer data, business operations, and organizational reputation.

## Recommendation

* **Patch CVE-2026-15158**: Immediately update the Blocksy Companion Pro plugin to a patched version (2.1.47 or newer) as soon as it becomes available.
* **Disable Vulnerable Extensions**: If immediate patching is not possible, disable the "WooCommerce Extra (Advanced Reviews)" and "Custom Fonts" extensions within Blocksy Companion Pro to mitigate the vulnerability until an update can be applied.
* **Implement Web Application Firewall (WAF) Rules**: Configure your WAF to inspect `multipart/form-data` uploads and block files with double extensions (e.g., `*.woff2.php`, `*.ttf.php`) when uploaded to WordPress plugin endpoints like `admin-ajax.php`.

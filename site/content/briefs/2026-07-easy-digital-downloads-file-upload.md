---
title: Easy Digital Downloads Plugin Arbitrary File Upload Leads to RCE (CVE-2026-12476)
slug: 2026-07-easy-digital-downloads-file-upload
description: The Easy Digital Downloads plugin for WordPress versions up to and including 3.6.9 is vulnerable to Arbitrary File Upload (CVE-2026-12476) due to insufficient file type validation, allowing authenticated attackers with Shop Manager-level access or higher to upload arbitrary files which can lead to remote code execution.
date: "2026-07-29T04:19:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web
  - arbitrary-file-upload
  - rce
  - wordpress
  - plugin
vendors:
  - Easy Digital Downloads
products:
  - Easy Digital Downloads plugin (<= 3.6.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Easy Digital Downloads plugin for WordPress is vulnerable to Arbitrary File Upload in versions up to and including 3.6.9.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: 'Server Software Component: Web Shell'
    evidence: This makes it possible for authenticated attackers...to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: 'Server Software Component: Web Shell'
    evidence: This makes it possible for authenticated attackers...to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-12476
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12476
rules:
  - title: Detect Possible CVE-2026-12476 Post-Exploitation Access
    description: Detects attempts to access potentially malicious executable files (web shells) uploaded via CVE-2026-12476 in the Easy Digital Downloads export directory.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, CVE-2026-12476, exists in the Easy Digital Downloads plugin for WordPress, affecting all versions up to and including 3.6.9. This flaw stems from improper file type validation within the `edd_do_ajax_import_file_upload()` function. Instead of robustly checking file contents or relying on WordPress's built-in MIME enforcement (`wp_handle_upload()`), the function only inspects the client-supplied `$_FILES['edd-import-file']['type']` Content-Type header against a narrow allow-list of CSV mime types. Following this superficial check, the `move_uploaded_file()` function is used, allowing files with arbitrary extensions (e.g., `.php` or `.phtml`) to be written to the web-accessible `wp-content/uploads/edd/exports/` directory. This makes it possible for authenticated attackers possessing Shop Manager-level access or higher to upload malicious files, such as web shells, ultimately leading to remote code execution on the compromised server. Defenders should prioritize patching and monitoring for suspicious file uploads and access attempts to the export directory.

## Attack Chain

1. An authenticated attacker with Shop Manager-level or higher privileges accesses the Easy Digital Downloads import file upload functionality, typically found within the WordPress administration interface.
2. The attacker crafts a malicious file, such as a PHP web shell (e.g., `shell.php`), designed to execute arbitrary commands on the server.
3. The attacker uploads the malicious file via the vulnerable `edd_do_ajax_import_file_upload()` function, manipulating the client-supplied `Content-Type` header to bypass the plugin's insufficient validation logic.
4. The `move_uploaded_file()` function writes the malicious file with its original, executable extension (e.g., `.php`) to the web-accessible directory: `wp-content/uploads/edd/exports/`.
5. The attacker sends an HTTP request to the newly uploaded malicious file, targeting its public URL (e.g., `example.com/wp-content/uploads/edd/exports/shell.php`).
6. The web server executes the malicious file, granting the attacker remote code execution capabilities on the underlying system, often as the web server's user.
7. The attacker can then perform further actions such as data exfiltration, creating persistent backdoors, or defacing the website.

## Impact

Successful exploitation of CVE-2026-12476 grants attackers remote code execution capabilities on the affected WordPress server. This allows for full compromise of the website, including data theft (e.g., customer information, payment details if stored on the server), website defacement, injection of malicious code into website content, and complete system takeover. Attackers can install persistent backdoors, launch further attacks against other systems, or use the compromised server as a pivot point within the network. The integrity, confidentiality, and availability of the affected WordPress site and potentially other systems on the same host are severely jeopardized.

## Recommendation

* Patch CVE-2026-12476 by updating the Easy Digital Downloads plugin to version 3.6.10 or later immediately.
* Deploy the Sigma rule "Detect Possible CVE-2026-12476 Post-Exploitation Access" to your SIEM and tune for your environment to identify attempts to access web shells in the Easy Digital Downloads export directory.
* Monitor web server access logs for suspicious HTTP POST requests to `/wp-admin/admin-ajax.php` containing `action=edd_do_ajax_import_file_upload`, especially if the `Content-Type` header is not a standard CSV type or if it contains suspicious filenames.
* Regularly review user accounts with Shop Manager-level access or higher, as these are prerequisites for exploiting this vulnerability.

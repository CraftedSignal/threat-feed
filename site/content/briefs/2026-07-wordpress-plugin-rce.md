---
title: 'CVE-2026-13430: WordPress Post Export Import with Media Plugin Arbitrary File Upload Leading to RCE'
slug: 2026-07-wordpress-plugin-rce
description: A high-severity arbitrary file upload vulnerability, CVE-2026-13430, exists in all versions up to 1.13.1 of the Post Export Import with Media plugin for WordPress, allowing authenticated administrators to upload executable web shells via a trailing-dot filename bypass, leading to remote code execution.
date: "2026-07-10T04:20:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - wordpress
  - arbitrary-file-upload
  - rce
products:
  - Post Export Import with Media plugin (<= 1.13.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: upload files that may be executable, which makes remote code execution possible
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: makes it possible for authenticated attackers... to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-13430
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13430
rules:
  - title: Detect CVE-2026-13430 Exploitation - Web Shell Access in WordPress Uploads
    description: Detects access to PHP files within the WordPress wp-content/uploads directory, which typically indicates a successful web shell upload via arbitrary file upload vulnerabilities like CVE-2026-13430.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-13430, has been identified in the "Post Export Import with Media" plugin for WordPress, impacting all versions up to, and including, 1.13.1. This flaw stems from insufficient file extension validation within the `import_media_file_secure` function, specifically exploiting a trailing-dot filename bypass. Attackers can craft a ZIP archive containing a malicious PHP file (e.g., `shell.php.`), which, when processed by the `ajax_import_media_start()` function, circumvents the extension allow-list check due to how `pathinfo()` handles the trailing dot. The file is initially extracted to a temporary location and subsequently copied to the WordPress uploads directory without re-validation, making it accessible as an executable web shell. This allows authenticated attackers with administrator-level access to achieve remote code execution on the compromised WordPress server.

## Attack Chain

1. An attacker obtains valid administrator-level credentials for a WordPress site running the vulnerable "Post Export Import with Media" plugin.
2. The attacker crafts a ZIP archive containing a malicious PHP web shell (e.g., `shell.php.`) with a trailing dot in its filename.
3. The attacker logs into the WordPress administration panel and initiates a media import process via the vulnerable plugin, uploading the crafted ZIP archive.
4. The plugin's `ajax_import_media_start()` function processes the ZIP entry; the `pathinfo()` function, when encountering the trailing dot (e.g., `shell.php.`), returns an empty string for the file extension.
5. This empty extension bypasses the plugin's allow-list validation check, treating the malicious PHP file as a benign file type.
6. The PHP web shell is extracted to a temporary directory on the web server.
7. The `import_media_file_secure()` function copies the extracted web shell from the temporary location to the `/wp-content/uploads/` directory without performing further extension re-validation.
8. The attacker browses to the newly uploaded web shell (e.g., `https://example.com/wp-content/uploads/shell.php`), gaining remote code execution on the web server and potentially full system compromise.

## Impact

Successful exploitation of CVE-2026-13430 allows an authenticated attacker with administrator privileges to achieve remote code execution on the WordPress server. This can lead to complete compromise of the website, including defacement, data theft from the database, further network pivot within the hosting environment, or use of the server for malicious activities such as hosting malware or launching attacks against other systems. The widespread use of WordPress and its plugins means many organizations could be exposed if they do not promptly patch this vulnerability.

## Recommendation

* Immediately update the "Post Export Import with Media" plugin to a patched version once available to address CVE-2026-13430.
* Deploy the provided Sigma rule to detect post-exploitation web shell access within your WordPress uploads directory.
* Configure web application firewall (WAF) rules to inspect uploaded files for suspicious content and extensions, specifically blocking uploads of PHP files into media directories.
* Regularly review administrator accounts on your WordPress installations for any unauthorized or suspicious activity.

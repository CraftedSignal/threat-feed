---
title: WordPress Drag and Drop File Upload Plugin Vulnerable to Arbitrary File Upload (CVE-2026-5364)
slug: 2024-01-wordpress-plugin-upload
description: The Drag and Drop File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file upload in versions up to 1.1.3, allowing unauthenticated attackers to upload arbitrary PHP files by manipulating the file type parameter and exploiting extension sanitization vulnerabilities.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - file-upload
  - rce
  - plugin
  - CVE-2026-5364
vendors:
  - WordPress
products:
  - Drag and Drop File Upload for Contact Form 7 plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-5364
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5364
rules:
  - title: Detect Suspicious File Upload via Drag and Drop CF7
    description: Detects potential exploitation of the Drag and Drop File Upload for Contact Form 7 plugin vulnerability (CVE-2026-5364) by monitoring for suspicious file extensions in HTTP POST requests to the plugin's upload endpoint.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-5364
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Upload via Drag and Drop CF7 - UNC Path
    description: Detects potential exploitation of the Drag and Drop File Upload for Contact Form 7 plugin vulnerability (CVE-2026-5364) by monitoring for suspicious file extensions in HTTP POST requests to the plugin's upload endpoint. Looks for UNC paths which are also an indicator of suspicious activity
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-5364
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Drag and Drop File Upload for Contact Form 7 plugin for WordPress, in versions up to and including 1.1.3, contains an arbitrary file upload vulnerability tracked as CVE-2026-5364. The flaw stems from insufficient sanitization of file extensions during the upload process. Specifically, the plugin extracts the file extension before sanitization and allows the file type parameter to be controlled by the attacker. Furthermore, validation occurs on the unsanitized extension, while the file is saved with a sanitized extension, stripping special characters like '$' during the save. While an .htaccess file and name randomization are present, these restrictions may be bypassable in certain configurations or by exploiting other vulnerabilities. This vulnerability could allow unauthenticated attackers to upload arbitrary PHP files to the web server, potentially leading to remote code execution (RCE).

## Attack Chain

1. An unauthenticated attacker identifies a WordPress website using a vulnerable version (<= 1.1.3) of the "Drag and Drop File Upload for Contact Form 7" plugin.
2. The attacker crafts a malicious HTTP POST request targeting the plugin's upload endpoint, typically `/wp-content/plugins/drag-and-drop-multiple-file-upload-contact-form-7/upload.php`.
3. The POST request includes a file with a manipulated extension, such as `evil.php$.jpg`, where `evil.php` is the malicious PHP payload and `$.jpg` is designed to be sanitized to `.jpg`.
4. The attacker modifies the `file type` parameter in the request to reflect the original manipulated file extension (`evil.php$.jpg`).
5. The plugin validates the extension against administrator-configured types but, due to the unsanitized extension and attacker control over the file type parameter, the malicious file passes validation.
6. The plugin sanitizes the extension, removing the `$` character, resulting in a file saved with the extension `.php`.
7. The attacker attempts to access the uploaded PHP file via a direct HTTP request to `/wp-content/uploads/<random_name>.php`.
8. If the `.htaccess` restrictions are bypassed (e.g., due to misconfiguration or another vulnerability), the web server executes the malicious PHP code, granting the attacker remote code execution.

## Impact

Successful exploitation of CVE-2026-5364 allows unauthenticated attackers to upload and execute arbitrary PHP code on the target WordPress server. This can lead to complete compromise of the website, including defacement, data theft, and installation of backdoors. While the presence of `.htaccess` and name randomization mitigates the risk, these protections may be bypassed, especially when combined with other vulnerabilities or misconfigurations. Given the widespread use of WordPress and its plugins, this vulnerability poses a significant risk to a large number of websites. The CVSS v3.1 base score is 8.1, indicating a high severity vulnerability.

## Recommendation

*   Upgrade the "Drag and Drop File Upload for Contact Form 7" plugin to the latest version (greater than 1.1.3) to patch CVE-2026-5364.
*   Implement a Web Application Firewall (WAF) rule to inspect and block requests containing suspicious file extensions in the POST parameters targeting the plugin's upload endpoint (`/wp-content/plugins/drag-and-drop-multiple-file-upload-contact-form-7/upload.php`).
*   Deploy the Sigma rule `Detect Suspicious File Upload via Drag and Drop CF7` to identify exploitation attempts in web server logs (cs-uri-query).
*   Review and harden `.htaccess` configurations to ensure that PHP execution is restricted in the `/wp-content/uploads/` directory.

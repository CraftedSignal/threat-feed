---
title: GoDAM WordPress Plugin Arbitrary File Upload Vulnerability (CVE-2026-14282)
slug: 2026-07-godam-arbitrary-file-upload
description: An arbitrary file upload vulnerability exists in the GoDAM WordPress plugin versions up to and including 1.12.2 due to insufficient file type validation in the `save_video_file()` function, allowing unauthenticated attackers to upload arbitrary files to the server and potentially achieve remote code execution.
date: "2026-07-23T10:18:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - arbitrary-file-upload
  - remote-code-execution
  - web-exploitation
vendors:
  - GoDAM
  - WordPress
products:
  - GoDAM - Organize WordPress Media Library & File Manager with Unlimited Folders for Images, Vid... <= 1.12.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Vulnerable to arbitrary file uploads...This makes it possible for unauthenticated attackers to upload arbitrary files...
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
    evidence: '...upload arbitrary files on the affected site''s server which may make remote code execution possible.'
    confidence_band: high
cves:
  - id: CVE-2026-14282
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14282
rules:
  - title: Detects CVE-2026-14282 Exploitation - GoDAM Plugin Arbitrary File Upload
    description: Detects CVE-2026-14282 exploitation - arbitrary file upload attempts to the GoDAM WordPress plugin via admin-ajax.php with executable file extensions, indicative of remote code execution attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-14282 details a critical arbitrary file upload vulnerability affecting the GoDAM - Organize WordPress Media Library & File Manager with Unlimited Folders for Images, Videos & more plugin for WordPress, specifically in versions up to and including 1.12.2. The vulnerability stems from insufficient file type validation within the `save_video_file()` function. This function, which is hooked into WPForms' `wpforms_process_before_filter`, erroneously trusts the attacker-supplied `multipart/form-data` `Content-Type` header. Critically, it bypasses WordPress's standard `wp_handle_upload()` security mechanisms by directly using `$wp_filesystem->move()` to save the raw uploaded file, while `wp_unique_filename()` preserves the original, potentially malicious, filename. This flaw enables unauthenticated attackers to upload arbitrary files, such as PHP web shells, directly to the web-served directories of the compromised site, leading to potential remote code execution and full system compromise.

## Attack Chain

1. **Reconnaissance**: An unauthenticated attacker identifies a WordPress site running a vulnerable version of the GoDAM plugin (1.12.2 or earlier).
2. **Initial Access (File Upload)**: The attacker crafts a malicious HTTP POST request targeting the `wp-admin/admin-ajax.php` endpoint, which is commonly used by WordPress plugins to handle AJAX actions.
3. **Action Invocation**: The POST request includes an `action` parameter (e.g., `action=gdam_save_video_file`) specifically designed to invoke the vulnerable `save_video_file()` function within the GoDAM plugin.
4. **Malicious Payload Delivery**: The attacker includes a malicious file, such as a PHP web shell, within the `multipart/form-data` body of the request.
5. **Bypass and File Placement**: The `save_video_file()` function, due to its insufficient validation and direct file moving via `$wp_filesystem->move()` (bypassing `wp_handle_upload()`), saves the malicious file with its original executable extension (e.g., `.php`) to a web-accessible directory on the server.
6. **Remote Code Execution**: The attacker then sends a subsequent HTTP GET request directly to the URL of the uploaded web shell, executing arbitrary commands on the compromised WordPress server.
7. **Impact**: The successful execution of arbitrary commands grants the attacker full control over the WordPress instance and potentially the underlying server.

## Impact

Successful exploitation of CVE-2026-14282 allows unauthenticated attackers to upload arbitrary files, including web shells, to a vulnerable WordPress site. This grants remote code execution capabilities, leading to full compromise of the affected website. Attackers can deface the site, inject malicious scripts, steal sensitive data from the database, disrupt website operations, or install backdoors for persistent access. The high CVSS score of 9.8 indicates critical impact and ease of exploitation, making this a severe threat to organizations utilizing the vulnerable plugin.

## Recommendation

* Patch CVE-2026-14282 immediately by updating the GoDAM WordPress plugin to a version greater than 1.12.2.
* Deploy the `Detects CVE-2026-14282 Exploitation - GoDAM Plugin Arbitrary File Upload` Sigma rule to your SIEM to identify attempts to exploit this vulnerability.
* Enable comprehensive web server logging for HTTP POST requests, including `cs-method`, `cs-uri-stem`, `cs-uri-query`, and `request_body` if possible, to facilitate detection.
* Review WordPress server file system permissions to ensure web-accessible directories do not have write permissions for the web server user, if not strictly necessary.

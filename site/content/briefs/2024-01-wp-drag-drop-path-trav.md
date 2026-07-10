---
title: WordPress Drag and Drop Multiple File Upload Plugin Path Traversal Vulnerability
slug: 2024-01-wp-drag-drop-path-trav
description: The Drag and Drop Multiple File Upload for Contact Form 7 WordPress plugin is vulnerable to path traversal, allowing unauthenticated attackers to read arbitrary files within the 'wp-content' directory readable by the web server process.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - path-traversal
  - arbitrary-file-read
  - plugin-vulnerability
products:
  - Drag and Drop Multiple File Upload for Contact Form 7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5710
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5710
rules:
  - title: Detect WordPress Drag and Drop Plugin Path Traversal
    description: Detects potential path traversal attempts in the Drag and Drop Multiple File Upload plugin for WordPress by monitoring HTTP requests containing path traversal sequences in the 'mfile[]' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Drag and Drop Plugin File Access via Email
    description: Detects file access within the wp-content directory via email attachments when the 'Drag and Drop Multiple File Upload' plugin is used.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Drag and Drop Multiple File Upload plugin for Contact Form 7, versions up to and including 1.3.9.6, contains a path traversal vulnerability (CVE-2026-5710). This flaw allows unauthenticated attackers to read arbitrary files readable by the web server process within the WordPress 'wp-content' directory. The vulnerability stems from the plugin's reliance on client-supplied `mfile[]` POST values for email attachment selection without proper server-side validation. Specifically, the plugin lacks path canonicalization, directory containment boundary enforcement, and upload provenance checks, making it susceptible to path traversal attacks. Successful exploitation results in sensitive file disclosure via email attachments.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the vulnerable "Drag and Drop Multiple File Upload for Contact Form 7" plugin.
2. The attacker crafts a malicious HTTP POST request to a Contact Form 7 endpoint on the WordPress site.
3. The POST request includes a `mfile[]` parameter containing a path traversal sequence (e.g., `../../../../wp-config.php`).
4. The `dnd_wpcf7_posted_data()` function processes the `mfile[]` value without sanitization, appending the user-supplied filename to the plugin's upload URL.
5. The `dnd_cf7_mail_components()` function converts the URL to a filesystem path using `str_replace()`.
6. The `file_exists()` function is used as a check, but the path traversal allows access to files outside the intended directory.
7. The targeted file (e.g., `wp-config.php`) is attached to an outgoing Contact Form 7 email as an attachment.
8. The attacker retrieves the email (if possible) or monitors for successful email transmission, gaining access to the contents of the targeted file.

## Impact

Successful exploitation of this path traversal vulnerability allows unauthenticated attackers to read arbitrary files within the 'wp-content' directory that are accessible to the web server process. This may include sensitive configuration files (e.g., `wp-config.php` containing database credentials), plugin code, and uploaded media. The impact is limited to the 'wp-content' directory due to the `wpcf7_is_file_path_in_content_dir()` function within the Contact Form 7 plugin which performs a check to ensure that the requested file is within that folder.

## Recommendation

*   Upgrade the "Drag and Drop Multiple File Upload for Contact Form 7" plugin to a version higher than 1.3.9.6 to patch CVE-2026-5710.
*   Deploy the provided Sigma rule `Detect WordPress Drag and Drop Plugin Path Traversal` to identify attempts to exploit this vulnerability via HTTP requests.
*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., `../`, `..%2f`) in the `mfile[]` parameter to detect exploitation attempts.

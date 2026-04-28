---
title: Everest Forms Plugin Arbitrary File Read and Deletion Vulnerability
slug: 2026-08-everest-forms-rfi-rce
description: The Everest Forms plugin for WordPress is vulnerable to arbitrary file read and deletion, allowing unauthenticated attackers to access sensitive data or cause denial of service by manipulating the 'old_files' parameter in versions up to 3.4.4.
date: "2026-04-20T20:35:20Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - wordpress
  - plugin
  - file-read
  - file-deletion
  - cve-2026-5478
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-5478
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5478
rules:
  - title: Detect Everest Forms Arbitrary File Read Attempt
    description: Detects attempts to exploit the Everest Forms plugin vulnerability (CVE-2026-5478) by identifying path traversal sequences in HTTP POST requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Deletion by Web Server User
    description: Detects potential exploitation of CVE-2026-5478 by monitoring file deletion events performed by the web server user, focusing on sensitive files.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Everest Forms plugin for WordPress, versions 3.4.4 and earlier, contains an arbitrary file read and deletion vulnerability (CVE-2026-5478). This flaw stems from the plugin's improper handling of the `old_files` parameter within form submissions. Specifically, the plugin trusts attacker-controlled data as legitimate server-side upload state and insecurely converts URLs into local filesystem paths without adequate sanitization. This lack of input validation enables unauthenticated attackers to inject path traversal sequences, leading to the disclosure of sensitive files like `wp-config.php`, which contains database credentials and authentication salts. Furthermore, the flawed path resolution is utilized in a post-email cleanup routine, resulting in arbitrary file deletion via the `unlink()` function, potentially causing a denial-of-service condition. Successful exploitation requires a form with a file-upload or image-upload field and the "store entry information" feature disabled.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP POST request to a WordPress page containing an Everest Forms form with a file upload field.
2. The attacker includes the `old_files` parameter in the POST data, injecting a path traversal payload (e.g., `../../../../wp-config.php`) into its value.
3. The WordPress application processes the form submission, and the Everest Forms plugin extracts the `old_files` parameter.
4. The plugin's flawed logic converts the attacker-supplied URL into a local file system path using regex-based string replacement without canonicalization or directory boundary enforcement.
5. The plugin attaches the resolved file (e.g., `/var/www/wordpress/../../../../wp-config.php`) to the notification email.
6. After sending the notification email, the post-email cleanup routine utilizes the same flawed path resolution to determine the file to delete.
7. The `unlink()` function is called on the resolved path, leading to the deletion of the targeted file (e.g., `wp-config.php`).
8. The attacker gains access to sensitive information (database credentials, salts) or causes a denial of service by deleting critical system files.

## Impact

Successful exploitation of CVE-2026-5478 allows unauthenticated attackers to read arbitrary files on the WordPress server, potentially exposing sensitive information like database credentials and authentication salts stored in `wp-config.php`. This could lead to full site compromise, including data theft, defacement, or further malicious activities. Furthermore, the ability to delete arbitrary files enables attackers to cause a denial-of-service condition by removing critical system or application files. The impact is significant as it affects all versions of the Everest Forms plugin up to and including 3.4.4.

## Recommendation

*   Immediately update the Everest Forms plugin to a version higher than 3.4.4 to patch CVE-2026-5478.
*   Deploy the Sigma rule "Detect Everest Forms Arbitrary File Read Attempt" to identify potential exploitation attempts in web server logs.
*   Enable web server logging to capture HTTP POST requests, which are crucial for detecting path traversal attempts (cs-uri-query, cs-method in webserver logs).
*   Monitor file deletion events on the WordPress server, especially those initiated by the web server user, using a file integrity monitoring (FIM) solution (file_event logs).
*   Implement input validation and sanitization for all user-supplied data, especially file paths, to prevent path traversal vulnerabilities.

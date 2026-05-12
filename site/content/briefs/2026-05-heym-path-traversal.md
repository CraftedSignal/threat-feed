---
title: Heym Path Traversal Vulnerability in File Upload Endpoint (CVE-2026-45225)
slug: 2026-05-heym-path-traversal
description: Heym before 0.0.21 is vulnerable to path traversal, allowing authenticated users to write attacker-controlled files to arbitrary locations by exploiting the unvalidated filename parameter in the upload_file() handler (CVE-2026-45225).
date: "2026-05-12T22:22:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-upload
  - CVE-2026-45225
vendors:
  - Heym
products:
  - Heym
  - heymrun/heym
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-45225
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45225
  - https://github.com/heymrun/heym/commit/835843e6d2bf7d018cbb8e50f28f0426eaa20c84
  - https://github.com/heymrun/heym/pull/92
  - https://github.com/heymrun/heym/releases/tag/v0.0.21
  - https://www.vulncheck.com/advisories/heym-path-traversal-file-upload-via-upload-file
rules:
  - title: Detect Heym Path Traversal File Upload (CVE-2026-45225)
    description: Detects CVE-2026-45225 exploitation — HTTP requests to the file upload endpoint containing path traversal sequences in the filename parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Heym Path Traversal Attempt via Crafted Filename (CVE-2026-45225)
    description: Detects CVE-2026-45225 attempt — Crafted filenames containing traversal sequences during file operations.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Heym before version 0.0.21 contains a path traversal vulnerability in its file upload endpoint. This flaw allows authenticated users to write malicious files to arbitrary locations on the server. By crafting a filename containing traversal sequences (e.g., ../../), an attacker can bypass intended path restrictions and manipulate files outside of the designated upload directory. This vulnerability affects the `upload_file()` handler due to insufficient validation of the filename parameter. Successful exploitation could lead to arbitrary file write, read, or even deletion, potentially compromising the entire system.

## Attack Chain

1.  Attacker authenticates to the Heym application.
2.  Attacker crafts a malicious filename containing path traversal sequences (e.g., `../../../evil.php`).
3.  Attacker initiates a file upload request to the `upload_file()` endpoint, including the crafted filename.
4.  The `upload_file()` handler receives the request but fails to properly sanitize the filename.
5.  The application writes the uploaded file to a location outside the intended directory, based on the path provided in the crafted filename.
6.  The attacker triggers execution of the uploaded file (e.g. if it's a PHP file).
7.  The attacker achieves arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows an attacker to write, read, or delete files outside the intended storage directory. This can lead to arbitrary code execution, allowing the attacker to gain complete control over the affected system. The CVSS v3.1 base score for this vulnerability is 7.6 (High), indicating a significant risk. The potential impact includes unauthorized access to sensitive data, modification of critical system files, and complete system compromise.

## Recommendation

*   Upgrade Heym to version 0.0.21 or later to patch CVE-2026-45225.
*   Implement robust filename validation and sanitization within the `upload_file()` handler to prevent path traversal attacks.
*   Deploy the Sigma rule `Detect Heym Path Traversal File Upload (CVE-2026-45225)` to detect exploitation attempts in web server logs.
*   Monitor web server logs for HTTP requests to the file upload endpoint containing suspicious filename patterns.

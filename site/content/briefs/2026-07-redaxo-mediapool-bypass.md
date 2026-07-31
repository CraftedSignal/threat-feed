---
title: Redaxo Mediapool File Extension Validation Bypass and RCE
slug: 2026-07-redaxo-mediapool-bypass
description: A security regression in Redaxo allows authenticated backend users to achieve RCE by bypassing extension filters using multi-segment filenames on misconfigured Apache web servers.
date: "2026-07-31T19:45:35Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Redaxo
products:
  - redaxo/core
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A security regression in Redaxo's Mediapool upload validator allows authenticated backend users to bypass filename extension checks by using multi-segment extensions.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: On web servers configured with loose PHP handler mappings, this allows an attacker to upload and execute arbitrary PHP code, leading to RCE.
    confidence_band: high
rules:
  - title: Detect Suspicious Multi-Extension Upload Attempt
    description: Detects potential bypass attempts by identifying filenames with multiple extensions where a sensitive extension (e.g., .php) is not the final segment.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A security regression in the `rex_mediapool::isAllowedExtension` function, introduced in commit `9d008697d`, allows authenticated backend users to bypass filename extension filters within the REDAXO CMS (versions 5.18.2 through 5.21.0). The validator previously utilized a robust `str_contains` check to block forbidden extensions (like .php) anywhere in the filename, but was refactored to use `str_ends_with` logic. This new implementation only checks the final extension and the immediate preceding segment, failing to account for multi-segment extensions like `shell.php.any.jpg`. 

Authenticated users with media upload privileges can upload polyglot files containing malicious PHP code. If the underlying web server (typically Apache) is configured with non-anchored PHP handlers (using `AddHandler` or overly broad `FilesMatch` regex), the server will execute the embedded PHP code when the uploaded file is requested, resulting in arbitrary code execution as the web-server user. This vulnerability is tracked as CVE-2026-53599.

## Attack Chain

1. Attacker gains access to a REDAXO backend account with the `media[upload]` permission.
2. Attacker crafts a polyglot file (e.g., `shell.php.any.jpg`) that contains a valid JPEG header followed by arbitrary PHP code.
3. Attacker navigates to the Media Pool upload interface and uploads the crafted `shell.php.any.jpg`.
4. The `isAllowedExtension` validator processes the filename, evaluates the final `.jpg` extension, and fails to identify the nested `.php` segment, allowing the upload.
5. The file is saved to the public `media/` directory.
6. Attacker sends an HTTP GET request to `https://<victim>/media/shell.php.any.jpg`.
7. The Apache web server, due to loose handler configuration, interprets the `.php` segment as a valid PHP execution directive.
8. The PHP engine executes the embedded payload, granting the attacker RCE.

## Impact

Successful exploitation allows an authenticated backend user to gain arbitrary PHP code execution on the target server. This enables full compromise of the web application, potential lateral movement within the hosting environment, and unauthorized access to data stored in the database and file system. The scope includes any deployment running vulnerable REDAXO versions configured with loose Apache PHP handler mappings.

## Recommendation

Prioritized actions for detection and remediation:

- Update REDAXO to version 5.21.1 or later to apply the security patch for CVE-2026-53599.
- Audit Apache configuration files for `AddHandler` directives or `FilesMatch` regex patterns that lack an end-of-line anchor (`$`), which can cause multi-extension files to be incorrectly parsed as PHP.
- Use the provided Sigma rule to detect attempts to upload files with suspicious double or multi-extension naming patterns in web server logs or CMS audit logs.
- Implement strict upload validation on web application firewalls (WAF) to inspect filenames for nested forbidden extensions, specifically targeting the pattern `.*\.php\..*`.

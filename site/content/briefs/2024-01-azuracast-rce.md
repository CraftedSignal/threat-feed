---
title: AzuraCast Path Traversal Leads to Remote Code Execution
slug: 2024-01-azuracast-rce
description: AzuraCast is vulnerable to path traversal in the Flow.js media upload endpoint, allowing authenticated users with media permissions to write arbitrary files, leading to remote code execution via PHP webshell upload.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - rce
  - azuracast
  - webserver
vendors:
  - composer
products:
  - azuracast (<= 0.23.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-vp2f-cqqp-478j
iocs:
  - type: url
    value: http://localhost/api/station/1/files/upload
  - type: url
    value: http://localhost/shell.php?cmd=id
  - type: file
    value: shell.php
ioc_counts:
  file: 1
  url: 2
rules:
  - title: Detect AzuraCast Webshell Upload via Path Traversal
    description: Detects attempts to upload PHP webshells to AzuraCast via path traversal in the 'currentDirectory' parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect Webshell Access in AzuraCast Web Root
    description: Detects access to PHP files in the AzuraCast web root, potentially indicating webshell activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AzuraCast, a self-hosted web radio management suite, is susceptible to a critical path traversal vulnerability (CVE-2026-42605) in its Flow.js media upload endpoint (`/api/station/{station_id}/files/upload`). This flaw allows an authenticated user with media management permissions, such as a DJ or station manager, to bypass file storage directory restrictions. By manipulating the `currentDirectory` parameter during file uploads, attackers can write arbitrary files to locations outside the intended media directory. The vulnerability is present in versions up to and including 0.23.5, and exploitation leads to remote code execution via PHP webshell upload, potentially resulting in full server compromise. The default local filesystem storage backend is required for exploitation; S3 or remote storage is not vulnerable.

## Attack Chain

1. The attacker authenticates to the AzuraCast web interface with a valid user account that has the `StationPermissions::Media` permission (e.g., DJ or Station Manager).
2. The attacker crafts a malicious HTTP POST request to the `/api/station/{station_id}/files/upload` endpoint, targeting a station that uses local storage.
3. The request includes a `currentDirectory` parameter containing path traversal sequences (e.g., `../../../../../var/azuracast/www/public`).
4. The request also includes a PHP webshell file (`shell.php`) as the `file_data` parameter.
5. The server-side code in `FlowUploadAction.php` concatenates the unsanitized `currentDirectory` value with the sanitized filename.
6. The server attempts to process the uploaded file, but the `.php` extension triggers a `CannotProcessMediaException`.
7. The `finally` block in `MediaProcessor.php` executes, calling `LocalFilesystem::upload()` to copy the file to the concatenated path, bypassing normal path sanitization due to `PathPrefixer::prefixPath()`.
8. The webshell is written to the web root, allowing the attacker to execute arbitrary commands by accessing the webshell via HTTP.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the AzuraCast server. This can lead to full server compromise, including reading sensitive configuration files (database credentials, API keys), accessing all station data, modifying application code, and potentially escalating privileges to root. A DJ-level user, the lowest privileged role with media access, can achieve the equivalent of full system administrator access, resulting in data exfiltration and complete control over the AzuraCast instance.

## Recommendation

*   Apply the vendor-provided patch by sanitizing the `currentDirectory` parameter in `FlowUploadAction.php` using `UploadedFile::filterClientPath()` to prevent path traversal.
*   Implement path normalization in `LocalFilesystem::upload()` to prevent traversal even after concatenation, as described in the advisory.
*   Deploy the Sigma rule "Detect AzuraCast Webshell Upload via Path Traversal" to identify exploitation attempts based on suspicious `currentDirectory` parameters.
*   Monitor web server logs for access to unusual PHP files in the web root directory, such as `shell.php` as described in the PoC.
*   Ensure that AzuraCast instances do not grant excessive permissions to users; minimize the number of accounts with `StationPermissions::Media`.

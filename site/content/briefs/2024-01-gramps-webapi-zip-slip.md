---
title: Gramps Web API Zip Slip Vulnerability in Media Archive Import
slug: 2024-01-gramps-webapi-zip-slip
description: A path traversal vulnerability (Zip Slip) exists in the gramps-webapi media archive import feature, allowing authenticated users with owner privileges to write arbitrary files outside the intended temporary extraction directory via malicious ZIP files, potentially leading to data corruption or replacement.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - zip-slip
  - gramps-webapi
  - vulnerability
vendors:
  - Gramps
products:
  - Gramps Web API
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Impair System
references:
  - https://github.com/advisories/GHSA-m5gr-86j6-99jp
rules:
  - title: Detect Suspicious Media Archive Import Requests
    description: Detects potential attempts to exploit the Zip Slip vulnerability via suspicious POST requests to the media archive import endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Write to Sensitive Directories via Gramps Web API
    description: Detects file writes to sensitive directories by the Gramps Web API process, potentially indicating successful exploitation of the Zip Slip vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical path traversal vulnerability, known as Zip Slip, has been identified in gramps-webapi versions 1.6.0 through 3.11.0. This flaw resides within the media archive import functionality and allows an authenticated user with owner-level privileges to upload a specially crafted ZIP file containing directory traversal sequences (../) in the filenames. Successful exploitation enables an attacker to write arbitrary files outside the designated temporary extraction directory on the server's local filesystem. The risk is highest in multi-tree deployments where tree owners are distinct from server administrators. The impact ranges from cross-tree data corruption to application config file overwrite, depending on the specific deployment configuration (SQLite+local media, Postgres+S3 media, or Postgres+S3+env-var-only config).

## Attack Chain

1.  Attacker authenticates to the gramps-webapi instance with owner-level privileges.
2.  Attacker crafts a malicious ZIP archive containing files with filenames including directory traversal sequences such as `../`.
3.  The attacker uploads the malicious ZIP archive via the media archive import feature.
4.  The `MediaImporter._check_disk_space_and_extract()` function in `gramps_webapi/api/media_importer.py` is called.
5.  The `zipfile.extractall()` function extracts the contents of the ZIP archive without proper validation of entry names.
6.  Due to the lack of sanitization, files are extracted to locations outside the intended temporary directory.
7.  Depending on the server configuration, the attacker overwrites sensitive files such as database files, media files, or application configuration files.
8.  The attacker achieves persistent code execution or data corruption within the gramps-webapi instance.

## Impact

Successful exploitation of this vulnerability can lead to several critical consequences. In multi-tree deployments, an attacker can overwrite another tree's database or media files, causing cross-tree data corruption or replacement. In deployments using local media storage, sensitive application configuration files can be overwritten. Even in configurations using Postgres and S3 storage with environment variable-based configurations, the attacker can write to ephemeral container storage, potentially disrupting service until a worker restart. The impact is most significant in multi-tree environments where owner privileges are granted to untrusted users.

## Recommendation

*   Apply the patch provided by gramps-webapi that validates ZIP entry names against the resolved real path of the temporary directory before extraction, preventing writes outside the intended directory, or upgrade to a non-vulnerable version.
*   For multi-tree deployments, review and restrict owner-level privileges to trusted users only to mitigate the risk of malicious archive uploads.
*   Monitor web server logs for suspicious POST requests to the media archive import endpoint, potentially indicating attempts to upload malicious ZIP files. Create a Sigma rule to detect this activity based on unusual URI parameters (see example rule below).
*   Implement file integrity monitoring on sensitive files and directories (e.g., database files, media directories, application configuration files) to detect unauthorized modifications. Use file_event logs to alert on these changes.

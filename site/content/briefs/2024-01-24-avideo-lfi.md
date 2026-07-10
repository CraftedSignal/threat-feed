---
title: WWBN AVideo Arbitrary Local File Read Vulnerability (CVE-2026-33354)
slug: 2024-01-24-avideo-lfi
description: WWBN AVideo versions up to 26.0 are vulnerable to an arbitrary local file read via the `chunkFile` parameter in the `POST /objects/aVideoEncoder.json.php` endpoint, allowing authenticated users to read sensitive server files.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - lfi
  - cve-2026-33354
  - webserver
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33354
rules:
  - title: Detect AVideo ChunkFile LFI Attempt
    description: Detects potential local file inclusion attempts via the chunkFile parameter in AVideo's aVideoEncoder.json.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo ChunkFile LFI Attempt - PHP Exclusion Bypass
    description: Detects potential local file inclusion attempts via the chunkFile parameter in AVideo's aVideoEncoder.json.php endpoint, specifically targeting bypasses of .php exclusion.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is susceptible to an arbitrary local file read vulnerability (CVE-2026-33354) in versions up to and including 26.0. The vulnerability resides in the `POST /objects/aVideoEncoder.json.php` endpoint, which processes `chunkFile` parameters intended for handling staged upload chunks. However, the application fails to adequately restrict the file paths provided through this parameter. An authenticated user, with privileges to edit their own videos, can manipulate the `chunkFile` parameter to specify arbitrary local file paths. The application's `isValidURLOrPath()` helper function, designed to validate file paths, permits access to files within broad server directories such as `/var/www/`, the application root, cache, `tmp`, and `videos`, effectively bypassing security measures and enabling unauthorized file access. This vulnerability allows an attacker to read sensitive files from the server, potentially exposing configuration details, database credentials, or other confidential information. A patch addressing this issue is available in commit 59bbd601a3f65a5b18c1d9e4eb11471c0a59214f.

## Attack Chain

1. Attacker authenticates to the AVideo platform with a valid user account that has permission to edit videos.
2. The attacker identifies a target file on the server they wish to read (e.g., `/var/www/avideo/configuration.php`).
3. The attacker crafts a `POST` request to `/objects/aVideoEncoder.json.php`.
4. In the `POST` request body, the attacker sets the `chunkFile` parameter to the absolute path of the target file (e.g., `chunkFile=/var/www/avideo/configuration.php`).
5. The AVideo application receives the request and calls `isValidURLOrPath()` on the supplied `chunkFile` value.
6. Since the path is within allowed directories and is not a `.php` file, `isValidURLOrPath()` returns true.
7. The application copies the content of the target file to the attacker's public video storage path.
8. The attacker accesses the copied file via HTTP from their video storage path.

## Impact

Successful exploitation of CVE-2026-33354 allows an attacker to read arbitrary files from the AVideo server, potentially leading to the disclosure of sensitive information such as configuration files, database credentials, or source code. This information can be used to further compromise the server, escalate privileges, or gain unauthorized access to user data. The number of victims depends on the deployment size of the vulnerable AVideo platform. Sectors affected could include media, education, and any organization using AVideo for video hosting.

## Recommendation

*   Upgrade AVideo to a version containing the patch from commit 59bbd601a3f65a5b18c1d9e4eb11471c0a59214f to remediate CVE-2026-33354.
*   Deploy the Sigma rule "Detect AVideo ChunkFile LFI Attempt" to your SIEM to detect exploitation attempts.
*   Monitor web server logs for `POST` requests to `/objects/aVideoEncoder.json.php` with suspicious `chunkFile` parameters referencing sensitive file paths.
*   Implement stricter input validation and sanitization for file paths used in file upload functionalities to prevent arbitrary file access.

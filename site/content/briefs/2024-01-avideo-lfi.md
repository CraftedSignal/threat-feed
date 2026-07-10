---
title: AVideo EncoderReceiveImage Local File Inclusion Vulnerability
slug: 2024-01-avideo-lfi
description: AVideo is vulnerable to local file inclusion (LFI) via the EncoderReceiveImage endpoint, allowing authenticated uploaders to read sensitive server files by bypassing path traversal restrictions.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - lfi
  - file-disclosure
  - php
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-39369
    cvss: 7.6
references:
  - https://github.com/advisories/GHSA-f4f9-627c-jh33
rules:
  - title: Detect AVideo LFI Attempt
    description: Detects attempts to exploit the local file inclusion vulnerability in AVideo's aVideoEncoderReceiveImage.json.php by identifying path traversal sequences in the downloadURL_gifimage parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo LFI via videos.json.php access
    description: Detects access to videos.json.php with showAll=1 following a POST request to aVideoEncoderReceiveImage.json.php, indicative of LFI exploitation.
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

AVideo, a video sharing platform, is vulnerable to a local file inclusion vulnerability (CVE-2026-39369) in versions 26.0 and earlier. The vulnerability exists in the `objects/aVideoEncoderReceiveImage.json.php` endpoint, which is accessible to authenticated users with uploader privileges. By manipulating the `downloadURL_gifimage` parameter with a specially crafted URL containing path traversal sequences, an attacker can bypass input sanitization and force the application to read arbitrary files from the server's filesystem. The application then writes the content of the file into a GIF, making it accessible via a public media URL. This allows attackers to retrieve sensitive information such as configuration files, source code, and system credentials.

## Attack Chain

1.  Attacker logs in to AVideo as an authenticated user with uploader privileges.
2.  Attacker crafts a malicious POST request to `objects/aVideoEncoderReceiveImage.json.php` with the `downloadURL_gifimage` parameter.
3.  The `downloadURL_gifimage` parameter contains a URL with path traversal sequences (e.g., `....//....//`) targeting a sensitive file on the server (e.g., `/etc/passwd`).
4.  The application attempts to sanitize the URL using `str_replace('../', '', ...)` but fails due to the overlapping traversal sequence.
5.  The application resolves the manipulated URL, resulting in a read operation from the targeted file on the local filesystem using `url_get_contents()` or `try_get_contents_from_local()`.
6.  The content of the targeted file is retrieved and written into a GIF image file on the server's disk.
7.  The attacker uses `objects/videos.json.php?showAll=1` to recover the generated GIF URL from `videosURL.gif.url`.
8.  The attacker accesses the GIF URL, retrieves the file content, and obtains sensitive information.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files on the AVideo server. This can lead to the disclosure of sensitive information, including configuration files, source code, and system credentials, potentially leading to further compromise of the server and the AVideo platform. This impacts any AVideo instance running version 26.0 or earlier and puts all associated data at risk.

## Recommendation

*   Apply the recommended fixes from WWBN: Reject any remote image URL whose decoded path contains traversal markers.
*   Apply the recommended fixes from WWBN: Do not allow attacker-controlled same-origin `/videos/...` fetches to resolve into local file reads.
*   Apply the recommended fixes from WWBN: Constrain any local shortcut path handling with `realpath()` and strict base-directory allowlists.
*   Apply the recommended fixes from WWBN: Validate GIF content before saving it into public media storage.
*   Apply the recommended fixes from WWBN: Ensure invalid-image cleanup checks the correct destination path.
*   Deploy the Sigma rule `Detect AVideo LFI Attempt` to detect exploitation attempts against the `aVideoEncoderReceiveImage.json.php` endpoint.
*   Monitor web server logs for HTTP requests to `/objects/aVideoEncoderReceiveImage.json.php` containing path traversal sequences in the `downloadURL_gifimage` parameter.

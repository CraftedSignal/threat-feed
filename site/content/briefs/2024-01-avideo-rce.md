---
title: AVideo Remote Code Execution via Polyglot File Upload (CVE-2026-33647)
slug: 2024-01-avideo-rce
description: AVideo versions up to 26.0 are vulnerable to remote code execution (CVE-2026-33647) due to insufficient file validation in the `ImageGallery::saveFile()` method, allowing attackers to upload polyglot files with a `.php` extension to achieve code execution.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-33647
  - RCE
  - File Upload
  - AVideo
  - Polyglot
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33647
rules:
  - title: Detect Access to Suspicious PHP File Uploads
    description: Detects HTTP requests to PHP files within common web server upload directories, indicating potential exploitation of file upload vulnerabilities like CVE-2026-33647.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
  - title: Detect Web Server Process Creating PHP Files in Upload Directory
    description: Detects the creation of PHP files within a web server's upload directory, which may indicate an attempt to upload a malicious file for remote code execution.
    platform: sigma
    severity: high
    tactics:
      - persistence
    data_sources:
      - file_event
      - linux
rules_count: 2
---

AVideo, an open-source video platform, is susceptible to remote code execution (RCE) in versions up to and including 26.0 due to a flaw in the `ImageGallery::saveFile()` method. This vulnerability, identified as CVE-2026-33647, arises from the inadequate validation of uploaded files. Specifically, the system uses `finfo` for MIME type detection but relies on the user-supplied filename extension without proper sanitization. An attacker can leverage this weakness by crafting a polyglot file, embedding malicious PHP code within a seemingly benign JPEG image, and naming it with a `.php` extension. This bypasses the MIME type check, causing the file to be saved as an executable PHP file within a web-accessible directory. The vulnerability was patched in commit 345a8d3ece0ad1e1b71a704c1579cbf885d8f3ae. Successful exploitation grants the attacker the ability to execute arbitrary code on the AVideo server, leading to potential data breaches, system compromise, and service disruption.

## Attack Chain

1.  The attacker identifies an AVideo instance running a vulnerable version (<= 26.0).
2.  The attacker crafts a polyglot file. This file is a valid JPEG image with PHP code appended. The file is named with a `.php` extension (e.g., `evil.php`).
3.  The attacker uses the AVideo web interface, specifically the image upload functionality within `ImageGallery::saveFile()`, to upload the malicious `evil.php` file.
4.  The `ImageGallery::saveFile()` method uses `finfo` to check the MIME type of the uploaded file. Because the file starts with JPEG magic bytes, it passes the MIME type check.
5.  Due to the missing allowlist on the filename extension, the file is saved with the attacker-controlled `.php` extension.
6.  The file is saved in a web-accessible directory on the AVideo server.
7.  The attacker sends an HTTP request to the uploaded PHP file (e.g., `https://avideo.example.com/uploads/evil.php`).
8.  The web server executes the PHP code embedded within the `evil.php` file, granting the attacker remote code execution on the server.

## Impact

Successful exploitation of CVE-2026-33647 allows an attacker to execute arbitrary code on the AVideo server. This can lead to a full system compromise, including the ability to read and modify sensitive data, install malware, pivot to other systems on the network, and disrupt service availability. The impact depends on the privileges of the web server process. Given the nature of video platforms, successful attacks can also lead to defacement and distribution of malicious content.

## Recommendation

*   Apply the patch from commit `345a8d3ece0ad1e1b71a704c1579cbf885d8f3ae` to remediate CVE-2026-33647 immediately.
*   Implement strict allowlisting for file extensions in the `ImageGallery::saveFile()` method to prevent the upload of executable files.
*   Deploy the provided Sigma rule to detect potential attempts to exploit CVE-2026-33647 by monitoring for the execution of PHP files within the web server's upload directories.
*   Review webserver logs for suspicious requests to PHP files in upload directories for potential exploitation attempts (log source: webserver).

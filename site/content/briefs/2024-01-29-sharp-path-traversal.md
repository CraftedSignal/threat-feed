---
title: code16/sharp Package Vulnerable to Path Traversal via Unsanitized File Extension
slug: 2024-01-29-sharp-path-traversal
description: The code16/sharp package is vulnerable to path traversal due to improper sanitization of file extensions, allowing authenticated attackers to manipulate file paths to write files outside the intended temporary directory or overwrite critical files.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - php
  - code16/sharp
vendors:
  - code16
products:
  - sharp
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-9ffq-6457-8958
  - https://cwe.mitre.org/data/definitions/22.html
  - https://github.com/code16/sharp
rules:
  - title: Detect Path Traversal Attempts in Web Server Logs (code16/sharp)
    description: Detects potential path traversal attempts targeting the code16/sharp package by analyzing web server logs for suspicious filenames in request URIs.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect Malicious File Extensions with Path Separators
    description: Detects file uploads with extensions containing path separators, potentially indicating a path traversal attempt.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The code16/sharp package, a PHP framework component, is vulnerable to a path traversal flaw (CVE-2026-33686) affecting versions prior to 9.20.0. The vulnerability resides in the `FileUtil` class, specifically within the `explodeExtension()` function, where the file extension is extracted without proper sanitization. This allows an authenticated attacker to inject path separators into the extension, bypassing the `normalizeName()` function, which only cleans the base filename. This vulnerability, reported by zaurgsynv, poses a significant risk as it allows for arbitrary file writes and potential overwrites of critical system files. The issue was addressed in pull request #715 by implementing proper extension sanitization using `pathinfo(PATHINFO_EXTENSION)` and strict regex replacements.

## Attack Chain

1. An authenticated attacker identifies the vulnerable `FileUtil::explodeExtension()` function in the code16/sharp package.
2. The attacker crafts a malicious filename with a path traversal sequence embedded within the file extension (e.g., "image.jpg/../../.env").
3. The crafted filename is submitted to the application through a file upload or similar functionality that utilizes the vulnerable `FileUtil` class.
4. The `FileUtil::explodeExtension()` function extracts the malicious extension ("jpg/../../.env") without proper sanitization.
5. The `normalizeName()` function is called, but it only cleans the base filename ("image"), leaving the malicious extension untouched.
6. The unsanitized filename is passed to the `storeAs()` function.
7. The `storeAs()` function, using the attacker-controlled path, writes the file to an arbitrary location outside the intended temporary directory.
8. The attacker successfully overwrites a critical file (e.g., ".env" or configuration file), potentially leading to code execution or information disclosure.

## Impact

The path traversal vulnerability (CVE-2026-33686) in the code16/sharp package allows authenticated attackers to manipulate file paths and potentially overwrite existing files. This can lead to arbitrary code execution if critical configuration files are overwritten, or sensitive information disclosure if the attacker gains access to files outside of the intended directory. While specific victim numbers are unavailable, successful exploitation could compromise entire applications built using the code16/sharp package, with a potential impact ranging from data breaches to complete system takeover.

## Recommendation

*   Upgrade the `code16/sharp` package to version 9.20.0 or later to remediate CVE-2026-33686.
*   Deploy the provided Sigma rule to your SIEM to detect attempts to exploit this path traversal vulnerability in web server logs.
*   Review and harden file upload and processing mechanisms in your applications to prevent path traversal attacks, even with patched libraries.
*   Monitor web server logs for suspicious file upload requests containing path traversal sequences in filenames.

---
title: File Browser EPUB Preview Stored XSS Vulnerability (CVE-2026-34529)
slug: 2026-04-filebrowser-xss
description: File Browser versions prior to 2.62.2 are vulnerable to stored cross-site scripting (XSS) via the EPUB preview function, allowing attackers to execute arbitrary JavaScript in a user's browser by embedding malicious code in a crafted EPUB file.
date: "2026-04-01T21:17:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - xss
  - filebrowser
  - cve-2026-34529
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34529
  - https://github.com/filebrowser/filebrowser/releases/tag/v2.62.2
  - https://github.com/filebrowser/filebrowser/security/advisories/GHSA-5vpr-4fgw-f69h
rules:
  - title: File Browser EPUB XSS Attempt via URI
    description: Detects potential XSS attempts in File Browser via suspicious URI parameters when accessing EPUB files.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1056
    data_sources:
      - webserver
      - linux
  - title: File Browser EPUB XSS Exploit - HTTP Referer
    description: Detects potential XSS exploitation attempts against File Browser EPUB functionality using HTTP Referer header.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

File Browser is a file management interface used for uploading, deleting, previewing, renaming, and editing files. A stored XSS vulnerability, identified as CVE-2026-34529, exists within the EPUB preview functionality of File Browser versions prior to 2.62.2. An attacker can exploit this vulnerability by crafting a malicious EPUB file containing embedded JavaScript. When a user previews the malicious EPUB file through the File Browser interface, the embedded JavaScript executes within their browser, potentially leading to session hijacking, defacement, or redirection to malicious websites. This vulnerability has been addressed in File Browser version 2.62.2.

## Attack Chain

1. Attacker crafts a malicious EPUB file containing embedded JavaScript designed for XSS exploitation.
2. Attacker uploads the malicious EPUB file to a File Browser instance. This could be achieved if the attacker has write access to the file system, via compromised credentials or anonymous upload functionality (if enabled).
3. A legitimate user, with access to the File Browser, navigates to the directory containing the malicious EPUB file.
4. The user previews the EPUB file using the File Browser's built-in preview function.
5. The File Browser processes the EPUB file, triggering the vulnerable code in the EPUB preview functionality.
6. The embedded JavaScript within the EPUB file executes in the user's browser in the context of the File Browser application.
7. The attacker's JavaScript payload can then perform actions such as stealing cookies, redirecting the user, or defacing the File Browser interface.
8. The attacker can use the stolen cookies to impersonate the user or further compromise the File Browser instance.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code within the context of a user's browser. This can lead to session hijacking, where an attacker steals a user's session cookie and impersonates them, potentially gaining unauthorized access to sensitive files and system resources. Further consequences include defacement of the File Browser interface, redirection of users to malicious websites, and potentially further compromise of the server hosting the File Browser application depending on the permissions of the compromised user account.

## Recommendation

*   Upgrade File Browser instances to version 2.62.2 or later to patch the XSS vulnerability (CVE-2026-34529).
*   Implement input validation and sanitization on file uploads to prevent the injection of malicious code.
*   Consider deploying a Content Security Policy (CSP) to restrict the execution of JavaScript from untrusted sources.
*   Enable logging on the webserver hosting File Browser to capture details of requests for EPUB files, which can be used to detect exploitation attempts.

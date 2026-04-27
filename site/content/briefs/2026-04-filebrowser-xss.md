---
title: File Browser EPUB Preview Stored XSS Vulnerability (CVE-2026-34529)
slug: 2026-04-filebrowser-xss
description: File Browser versions prior to 2.62.2 are vulnerable to stored cross-site scripting (XSS) via the EPUB preview function, allowing attackers to execute arbitrary JavaScript in a user's browser by embedding malicious code in a crafted EPUB file.
date: "2026-04-01T21:17:00Z"
severities:
  - medium
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

File Browser is a file management interface used for uploading, deleting, previewing, renaming, and editing files. A stored XSS vulnerability, identified as CVE-2026-34529, exists within the EPUB preview functionality of File Browser versions prior to 2.62.2. An attacker can exploit this vulnerability by crafting a malicious EPUB file containing embedded JavaScript. When a user previews the malicious EPUB file through the File Browser interface, the embedded JavaScript executes within their…

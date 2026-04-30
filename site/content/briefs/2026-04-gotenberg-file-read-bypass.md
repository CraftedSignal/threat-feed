---
title: Gotenberg Chromium Deny-List Bypass via Case-Insensitive URL Scheme
slug: 2026-04-gotenberg-file-read-bypass
description: Gotenberg versions before 8.29.0 are vulnerable to unauthenticated arbitrary file read, where a case-insensitive URL scheme bypasses the Chromium deny-list, allowing attackers to read sensitive files such as /etc/passwd by using mixed-case or uppercase URL schemes like FILE:///etc/passwd, leading to the leakage of sensitive data from the Gotenberg container and bypassing the fix for CVE-2024-21527.
date: "2026-03-30T16:16:57Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - gotenberg
  - file-read
  - vulnerability
  - chromium
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-jjwv-57xh-xr6r
rules:
  - title: Detect Gotenberg File Read Bypass via URL Scheme Case Manipulation
    description: Detects attempts to bypass the Gotenberg Chromium deny-list by using mixed-case or uppercase URL schemes to access local files.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Gotenberg HTML Conversion File Read Bypass via URL Scheme Case Manipulation
    description: Detects attempts to bypass the Gotenberg Chromium deny-list by using mixed-case or uppercase URL schemes in HTML conversion requests to access local files.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Gotenberg, a popular Docker-based solution for converting HTML, Markdown, and Office documents to PDF, is susceptible to a critical vulnerability in versions prior to 8.29.0. This flaw allows for unauthenticated arbitrary file read due to a bypass in the Chromium deny-list. The vulnerability stems from the application's failure to enforce case-sensitivity when validating URL schemes against the deny-list, implemented to prevent access to sensitive files. An attacker can exploit this by using…

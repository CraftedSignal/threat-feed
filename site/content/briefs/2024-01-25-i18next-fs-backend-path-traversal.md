---
title: i18next-fs-backend Path Traversal Vulnerability
slug: 2024-01-25-i18next-fs-backend-path-traversal
description: i18next-fs-backend versions before 2.6.4 are vulnerable to path traversal due to insufficient sanitization of the lng and ns values, potentially allowing attackers to read arbitrary files, overwrite files, or execute code if .js or .ts locale files are in use.
date: "2024-01-25T12:00:00Z"
severities:
  - high
tags:
  - path-traversal
  - i18next
  - arbitrary-file-read
  - arbitrary-file-write
  - code-execution
vendors:
  - npm
products:
  - i18next-fs-backend
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-8847-338w-5hcj
rules:
  - title: Detect i18next-fs-backend Path Traversal Attempt via HTTP Request
    description: Detects attempts to exploit the i18next-fs-backend path traversal vulnerability by identifying suspicious directory traversal sequences in the lng or ns parameters of HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect i18next-fs-backend .js/.ts Eval Code Execution Attempt
    description: Detects attempts to exploit the i18next-fs-backend .js/.ts eval vulnerability via malicious filenames.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The i18next-fs-backend library, a file system backend for the i18next internationalization framework, is vulnerable to a path traversal attack in versions prior to 2.6.4. This vulnerability arises from the unsanitized use of the `lng` (language) and `ns` (namespace) parameters when constructing file paths for loading and writing locale files. If an application exposes the language code to user input, an attacker can craft a malicious `lng` or `ns` value containing directory traversal sequences…

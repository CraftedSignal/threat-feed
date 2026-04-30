---
title: Sharp CMS Path Traversal Vulnerability (CVE-2026-33686)
slug: 2024-05-sharp-path-traversal
description: A path traversal vulnerability exists in Sharp CMS versions prior to 9.20.0 due to improper sanitization of file extensions, potentially allowing attackers to bypass security restrictions and access sensitive files.
date: "2026-03-26T22:16:31Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - cms
  - laravel
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33686
rules:
  - title: SharpCMS Path Traversal Upload
    description: Detects file upload attempts with path traversal sequences targeting Sharp CMS.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: SharpCMS Suspicious File Extension
    description: Detects requests with suspicious file extensions after a directory traversal
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Sharp CMS, a content management framework built for Laravel, is vulnerable to a path traversal attack. This vulnerability affects versions prior to 9.20.0 and stems from the `FileUtil` class not properly sanitizing file extensions. The flaw allows attackers to manipulate file paths by injecting path separators, potentially leading to unauthorized file access or manipulation within the storage layer. The vulnerability resides in the `FileUtil::explodeExtension()` function within…

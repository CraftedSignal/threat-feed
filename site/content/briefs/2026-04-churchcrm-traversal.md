---
title: ChurchCRM Path Traversal Vulnerability Leading to Remote Code Execution
slug: 2026-04-churchcrm-traversal
description: A path traversal vulnerability in ChurchCRM versions prior to 6.5.3 allows authenticated administrators to upload arbitrary files, leading to remote code execution by overwriting Apache .htaccess files.
date: "2026-04-07T18:16:41Z"
severities:
  - critical
tags:
  - path-traversal
  - rce
  - churchcrm
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-35573
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35573
rules:
  - title: ChurchCRM Suspicious File Upload
    description: Detects suspicious file uploads to ChurchCRM's backup directory with unusual extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: ChurchCRM .htaccess File Creation
    description: Detects the creation of .htaccess files in web directories, potentially indicating an attempt to modify web server behavior.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

ChurchCRM, an open-source church management system, is vulnerable to a path traversal attack affecting versions prior to 6.5.3. This vulnerability resides in the backup restore functionality, specifically within `src/ChurchCRM/Backup/RestoreJob.php`. Authenticated administrators can exploit this flaw by manipulating the `$rawUploadedFile['name']` parameter, which lacks proper sanitization. This allows for the upload of arbitrary files with attacker-controlled names to the…

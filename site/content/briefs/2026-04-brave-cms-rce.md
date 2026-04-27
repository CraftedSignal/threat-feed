---
title: Brave CMS Unrestricted File Upload Leads to Remote Code Execution
slug: 2026-04-brave-cms-rce
description: Brave CMS versions prior to 2.0.6 contain an unrestricted file upload vulnerability within the CKEditor upload functionality in the ckupload method, allowing authenticated users to upload executable PHP scripts and achieve Remote Code Execution.
date: "2026-04-06T18:16:42Z"
severities:
  - critical
tags:
  - cve-2026-35164
  - rce
  - file-upload
  - brave-cms
  - ckeditor
  - php
  - webserver
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35164
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35164
  - https://github.com/Ajax30/BraveCMS-2.0/security/advisories/GHSA-2j4q-6p52-4rhw
rules:
  - title: Detect Access to Suspicious PHP Files
    description: Detects attempts to access PHP files in common upload directories, which may indicate exploitation of file upload vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHP File Uploads via CKEditor
    description: Detects potential PHP file uploads via the CKEditor upload functionality.
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

Brave CMS, an open-source content management system, is vulnerable to an unrestricted file upload vulnerability (CVE-2026-35164) in versions prior to 2.0.6. The vulnerability resides within the CKEditor upload functionality, specifically in the `ckupload` method located in `app/Http/Controllers/Dashboard/CkEditorController.php`. The application fails to properly validate the types of uploaded files, relying solely on user-provided input. This lack of validation enables an authenticated user to…

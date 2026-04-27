---
title: Emlog Path Traversal Vulnerability Leads to Remote Code Execution
slug: 2024-01-emlog-rce
description: Emlog versions 2.6.2 and prior are vulnerable to path traversal via crafted ZIP uploads, allowing authenticated admins to write arbitrary files and achieve remote code execution.
date: "2026-04-03T23:17:04Z"
severities:
  - critical
tags:
  - path-traversal
  - remote-code-execution
  - emlog
  - web-application
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34607
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34607
rules:
  - title: Detect Web Request for Potentially Uploaded Webshell
    description: Detects requests to PHP files outside the webroot, indicating potential webshell uploads after exploiting CVE-2026-34607.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect Webshell Execution from Web Server Process
    description: Detects process creation events originating from web server processes, indicating potential webshell execution after exploiting CVE-2026-34607.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Emlog, an open-source website building system, is vulnerable to a critical path traversal vulnerability (CVE-2026-34607) affecting versions 2.6.2 and earlier. This flaw resides within the `emUnZip()` function located in `include/lib/common.php:793`. The vulnerability stems from the function's failure to sanitize ZIP entry names during extraction of ZIP archives, such as those used for plugin/template uploads or backup imports. An authenticated administrator can exploit this by uploading a…

---
title: Laravel Excel Arbitrary File Overwrite via Path Traversal
slug: 2026-09-laravel-excel-traversal
description: The Laravel Excel library (v3.1.8-v3.1.69) fails to properly sanitize the destination path in the store() method, allowing an attacker to overwrite arbitrary files writable by the PHP process via path traversal, leading to potential RCE.
date: "2026-09-08T21:53:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:maatwebsite:laravel_excel:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - rce
  - php
vendors:
  - Maatwebsite
products:
  - Laravel Excel (>= 3.1.8, < 3.1.70)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Overwriting a PHP file that is reachable by the web server (for example a front controller or a cached view) turns attacker-controlled row content into code execution.
    confidence_band: high
cves:
  - id: CVE-2026-84374
    cvss: 7.5
    epss: 0.00571
references:
  - https://github.com/advisories/GHSA-c7r6-vx3h-w5g2
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-84374
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade maatwebsite/excel to 3.1.70
      owner: IT Operations
      due: 48h
      evidence: Fixed in 3.1.70. Disk::copy() now always writes through the configured filesystem disk.
  mitigation_plan:
    - priority: immediate
      action: Sanitize all user-input paths for Excel export using basename() or path validation
      owner: Application Security
      addresses: CVE-2026-84374
      evidence: 'Workaround: validate the path before passing it to store() reject absolute paths and any .. segment'
---

Laravel Excel (maatwebsite/excel) versions 3.1.8 through 3.1.69 contain a path traversal vulnerability in the `Excel::store()` functionality. The library improperly resolves the destination path against the process working directory rather than the configured Flysystem disk. If the provided path resolves to an existing file, the library utilizes `fopen()` to write the export data directly to the filesystem, bypassing standard security abstractions.

An attacker able to control the `$filePath` argument passed to `Excel::store()` can force the application to overwrite critical system files, including web-accessible scripts like front controllers or cached views. Since the CSV and HTML writers include cell content verbatim, this overwrite primitive allows for the injection of malicious code. Exploitation requires the existing file to be writable by the PHP user and for the application to pass unsanitized input to the library.

## Impact

Successful exploitation results in an arbitrary file overwrite of any file accessible to the PHP process. When the target is a web-accessible script, this leads to Remote Code Execution (RCE). Applications delegating file naming or path construction to user request input are at high risk.

## Recommendation

* Upgrade to Laravel Excel version 3.1.70 or later, which ensures all writes are routed through the configured Flysystem disk.
* If upgrading is not immediately possible, implement server-side validation to reject absolute paths and directory traversal segments (e.g., `..`).
* Enforce strict filename sanitization using `basename()` on all user-supplied input before passing the value to `Excel::store()`.
* Audit application code for instances where user input flows into the path argument of `Excel::store()` or `->storeExcel()` calls.
